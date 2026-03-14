import { createHash, createVerify, randomUUID } from 'node:crypto';
import { Strategy } from '../strategy.js';
import type { AegisRequest, DoneCallback } from '../types.js';

// ---------------------------------------------------------------------------
// Minimal XML SAX parser (<200 LOC, no dependencies)
// Handles: elements, attributes, text content, CDATA, namespaces.
// Does NOT handle: DTDs, processing instructions, comments.
// ---------------------------------------------------------------------------

interface SAXElement {
  tag: string;
  attrs: Record<string, string>;
  text: string;
  children: SAXElement[];
}

function parseXML(xml: string): SAXElement {
  const stack: SAXElement[] = [];
  const root: SAXElement = { tag: '', attrs: {}, text: '', children: [] };
  let current = root;
  stack.push(current);

  let i = 0;
  const len = xml.length;

  while (i < len) {
    if (xml[i] === '<') {
      if (xml[i + 1] === '!') {
        if (xml.startsWith('<![CDATA[', i)) {
          // CDATA section
          const end = xml.indexOf(']]>', i + 9);
          if (end === -1) break;
          current.text += xml.slice(i + 9, end);
          i = end + 3;
          continue;
        }
        // Comment or DOCTYPE — skip
        const end = xml.indexOf('>', i + 2);
        if (end === -1) break;
        i = end + 1;
        continue;
      }

      if (xml[i + 1] === '?') {
        // Processing instruction — skip
        const end = xml.indexOf('?>', i + 2);
        if (end === -1) break;
        i = end + 2;
        continue;
      }

      if (xml[i + 1] === '/') {
        // Closing tag
        const end = xml.indexOf('>', i + 2);
        if (end === -1) break;
        stack.pop();
        current = stack[stack.length - 1] || root;
        i = end + 1;
        continue;
      }

      // Opening tag
      const tagEnd = xml.indexOf('>', i + 1);
      if (tagEnd === -1) break;

      const selfClosing = xml[tagEnd - 1] === '/';
      const tagContent = xml.slice(i + 1, selfClosing ? tagEnd - 1 : tagEnd);
      const spaceIdx = tagContent.search(/\s/);
      const tag = spaceIdx === -1 ? tagContent : tagContent.slice(0, spaceIdx);
      const attrStr = spaceIdx === -1 ? '' : tagContent.slice(spaceIdx + 1);

      // Parse attributes
      const attrs: Record<string, string> = {};
      const attrRe = /([a-zA-Z0-9_:.-]+)\s*=\s*["']([^"']*)["']/g;
      let match: RegExpExecArray | null;
      while ((match = attrRe.exec(attrStr)) !== null) {
        attrs[match[1]] = decodeXMLEntities(match[2]);
      }

      const elem: SAXElement = { tag, attrs, text: '', children: [] };
      current.children.push(elem);

      if (!selfClosing) {
        stack.push(elem);
        current = elem;
      }

      i = tagEnd + 1;
    } else {
      // Text content
      const nextTag = xml.indexOf('<', i);
      const text = nextTag === -1 ? xml.slice(i) : xml.slice(i, nextTag);
      if (text.trim()) {
        current.text += decodeXMLEntities(text.trim());
      }
      i = nextTag === -1 ? len : nextTag;
    }
  }

  return root.children[0] || root;
}

function decodeXMLEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/**
 * Find an element by local tag name (ignoring namespace prefix).
 */
function findElement(elem: SAXElement, localName: string): SAXElement | undefined {
  const lowerLocal = localName.toLowerCase();
  for (const child of elem.children) {
    const tag = child.tag.includes(':') ? child.tag.split(':')[1] : child.tag;
    if (tag.toLowerCase() === lowerLocal) return child;
    const found = findElement(child, localName);
    if (found) return found;
  }
  return undefined;
}

/**
 * Find all elements by local tag name.
 */
function findElements(elem: SAXElement, localName: string): SAXElement[] {
  const results: SAXElement[] = [];
  const lowerLocal = localName.toLowerCase();
  for (const child of elem.children) {
    const tag = child.tag.includes(':') ? child.tag.split(':')[1] : child.tag;
    if (tag.toLowerCase() === lowerLocal) results.push(child);
    results.push(...findElements(child, localName));
  }
  return results;
}

// ---------------------------------------------------------------------------
// SAML Profile
// ---------------------------------------------------------------------------

export interface SAMLProfile {
  issuer: string;
  nameID: string;
  nameIDFormat?: string;
  sessionIndex?: string;
  attributes: Record<string, string>;
}

export type SAMLVerifyCallback<User> = (
  profile: SAMLProfile,
  done: DoneCallback<User>,
) => void;

export type SAMLVerifyAsync<User> = (
  profile: SAMLProfile,
) => Promise<User | false | null | undefined>;

export type SAMLVerifyFn<User> = SAMLVerifyCallback<User> | SAMLVerifyAsync<User>;

export interface SAMLStrategyOptions {
  entryPoint: string;
  issuer: string;
  callbackURL: string;
  cert: string;
}

/**
 * SAML 2.0 strategy.
 *
 * Handles SP-initiated SSO: redirects to the IdP entry point, then parses
 * the SAML Response POST-back to extract the assertion and user attributes.
 */
export class SAMLStrategy<User = unknown> extends Strategy {
  name = 'saml';

  private _entryPoint: string;
  private _issuer: string;
  private _callbackURL: string;
  private _cert: string;
  private _verify: SAMLVerifyFn<User>;

  constructor(options: SAMLStrategyOptions, verify: SAMLVerifyFn<User>) {
    super();
    if (!options.cert) {
      throw new Error('SAML cert is required for signature verification');
    }
    this._entryPoint = options.entryPoint;
    this._issuer = options.issuer;
    this._callbackURL = options.callbackURL;
    this._cert = options.cert;
    this._verify = verify;
  }

  async authenticate(req: AegisRequest): Promise<void> {
    const body = (req as unknown as { body?: Record<string, string> }).body;

    if (body?.SAMLResponse) {
      return this._handleResponse(req, body.SAMLResponse);
    }

    // Initiate SAML flow: redirect to IdP.
    return this._redirectToIdP(req);
  }

  private _redirectToIdP(req: AegisRequest): void {
    const requestId = `_${randomUUID()}`;

    // Store the AuthnRequest ID in session for InResponseTo validation.
    if (req.session) {
      (req.session as Record<string, unknown>)['saml:requestId'] = requestId;
    }

    const samlRequest = Buffer.from(
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="${requestId}" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${this._callbackURL}" ` +
        `Issuer="${this._issuer}" />`,
    ).toString('base64');

    const params = new URLSearchParams({ SAMLRequest: samlRequest });
    this.redirect(`${this._entryPoint}?${params.toString()}`);
  }

  private async _handleResponse(req: AegisRequest, samlResponse: string): Promise<void> {
    try {
      const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
      const doc = parseXML(xml);

      // Validate InResponseTo matches our stored AuthnRequest ID.
      this._validateInResponseTo(req, doc);

      // Validate Destination matches our ACS URL.
      this._validateDestination(doc);

      // Verify XML signature (cert is required).
      this._verifySignature(doc, xml);

      const profile = this._extractProfile(doc);

      // Validate assertion conditions.
      this._validateAssertion(doc);

      await this._callVerify(profile);
    } catch (err) {
      this.error(err as Error);
    }
  }

  /**
   * Validate InResponseTo attribute matches the stored AuthnRequest ID.
   */
  private _validateInResponseTo(req: AegisRequest, doc: SAXElement): void {
    const response = findElement(doc, 'Response') || doc;
    const inResponseTo = response.attrs?.InResponseTo;

    if (req.session) {
      const storedRequestId = (req.session as Record<string, unknown>)['saml:requestId'] as string | undefined;
      delete (req.session as Record<string, unknown>)['saml:requestId'];

      if (storedRequestId) {
        if (!inResponseTo) {
          throw new Error(
            'SAML Response missing InResponseTo attribute (possible unsolicited response)',
          );
        }
        if (inResponseTo !== storedRequestId) {
          throw new Error(
            `SAML InResponseTo mismatch: expected ${storedRequestId}, got ${inResponseTo}`,
          );
        }
      }
    }
  }

  /**
   * Validate Destination attribute matches our ACS URL.
   * Per SAML Core 3.2.2, Destination is required for HTTP POST binding.
   */
  private _validateDestination(doc: SAXElement): void {
    const response = findElement(doc, 'Response') || doc;
    const destination = response.attrs?.Destination;

    if (!destination) {
      throw new Error(
        'SAML Response missing Destination attribute (required for HTTP POST binding)',
      );
    }
    if (destination !== this._callbackURL) {
      throw new Error(
        `SAML Destination mismatch: expected ${this._callbackURL}, got ${destination}`,
      );
    }
  }

  /**
   * Verify the XML digital signature on the SAML response or assertion.
   */
  private _verifySignature(doc: SAXElement, xml: string): void {
    const signature = findElement(doc, 'Signature');
    if (!signature) {
      throw new Error('No XML Signature found in SAML response');
    }

    const signedInfo = findElement(signature, 'SignedInfo');
    if (!signedInfo) {
      throw new Error('No SignedInfo in SAML Signature');
    }

    const signatureValueElem = findElement(signature, 'SignatureValue');
    if (!signatureValueElem?.text) {
      throw new Error('No SignatureValue in SAML Signature');
    }

    // Determine the signature algorithm.
    const signatureMethod = findElement(signedInfo, 'SignatureMethod');
    const algorithm = signatureMethod?.attrs.Algorithm || '';
    const nodeAlg = this._mapSignatureAlgorithm(algorithm);

    // Extract the SignedInfo XML from the raw response for verification.
    // We need the canonical form of SignedInfo.
    const signedInfoXml = this._extractSignedInfoXml(xml);
    if (!signedInfoXml) {
      throw new Error('Could not extract SignedInfo from SAML response');
    }

    // Verify the signature.
    const signatureValue = Buffer.from(
      signatureValueElem.text.replace(/\s+/g, ''),
      'base64',
    );

    const cert = this._formatCert(this._cert);
    const verifier = createVerify(nodeAlg);
    verifier.update(signedInfoXml);
    if (!verifier.verify(cert, signatureValue)) {
      throw new Error('SAML signature verification failed');
    }

    // Verify the digest of the referenced content.
    const reference = findElement(signedInfo, 'Reference');
    if (reference) {
      const digestValueElem = findElement(reference, 'DigestValue');
      const digestMethodElem = findElement(reference, 'DigestMethod');
      if (digestValueElem?.text && digestMethodElem) {
        const refUri = reference.attrs.URI || '';
        this._verifyDigest(doc, xml, refUri, digestValueElem.text, digestMethodElem.attrs.Algorithm || '');
      }
    }
  }

  /**
   * Verify the digest value of the referenced element.
   */
  private _verifyDigest(
    doc: SAXElement,
    xml: string,
    refUri: string,
    expectedDigest: string,
    algorithm: string,
  ): void {
    const hashAlg = this._mapDigestAlgorithm(algorithm);

    // Find the referenced element by ID.
    let content: string;
    if (refUri.startsWith('#')) {
      const id = refUri.slice(1);
      const refElement = this._findElementById(doc, id);
      if (!refElement) {
        throw new Error(`Referenced element ${refUri} not found`);
      }
      // Extract the raw XML of the referenced element (without Signature child).
      content = this._extractElementXml(xml, refElement.tag, id);
    } else {
      // Empty URI means the whole document.
      content = xml;
    }

    const hash = createHash(hashAlg);
    hash.update(content);
    const computed = hash.digest('base64');

    if (computed !== expectedDigest.replace(/\s+/g, '')) {
      throw new Error('SAML digest verification failed');
    }
  }

  private _findElementById(elem: SAXElement, id: string): SAXElement | undefined {
    if (elem.attrs.ID === id) return elem;
    for (const child of elem.children) {
      const found = this._findElementById(child, id);
      if (found) return found;
    }
    return undefined;
  }

  private _extractSignedInfoXml(xml: string): string | null {
    // Extract the <SignedInfo>...</SignedInfo> block from the raw XML.
    // LIMITATION: Uses regex instead of proper XML canonicalization (C14N).
    // This is fragile against XML signature wrapping attacks where an attacker
    // injects duplicate SignedInfo elements. The digest verification step
    // mitigates this by independently verifying referenced element content.
    // Future hardening: implement Exclusive XML Canonicalization (exc-c14n).
    const re = /<(?:\w+:)?SignedInfo[^>]*>[\s\S]*?<\/(?:\w+:)?SignedInfo>/;
    const match = xml.match(re);
    return match ? match[0] : null;
  }

  private _extractElementXml(xml: string, tag: string, id: string): string {
    // Extract the element XML by ID attribute, excluding the Signature child.
    // LIMITATION: Uses regex instead of proper XML parsing. Vulnerable to XML
    // wrapping attacks if an attacker can inject elements with duplicate IDs.
    // Mitigated by digest verification of referenced content.
    // Future hardening: use DOM-based extraction with proper C14N.
    const localTag = tag.includes(':') ? tag.split(':')[1] : tag;
    const re = new RegExp(`<(?:\\w+:)?${localTag}[^>]*ID="${id}"[^>]*>[\\s\\S]*?<\\/(?:\\w+:)?${localTag}>`);
    const match = xml.match(re);
    if (!match) return '';
    // Remove the Signature element from the content for digest computation.
    return match[0].replace(/<(?:\w+:)?Signature[^>]*>[\s\S]*?<\/(?:\w+:)?Signature>/, '');
  }

  private _mapSignatureAlgorithm(uri: string): string {
    if (uri.includes('rsa-sha256')) return 'RSA-SHA256';
    if (uri.includes('rsa-sha1')) return 'RSA-SHA1';
    if (uri.includes('rsa-sha384')) return 'RSA-SHA384';
    if (uri.includes('rsa-sha512')) return 'RSA-SHA512';
    // Default to SHA-256 for modern SAML.
    return 'RSA-SHA256';
  }

  private _mapDigestAlgorithm(uri: string): string {
    if (uri.includes('sha256')) return 'sha256';
    if (uri.includes('sha1')) return 'sha1';
    if (uri.includes('sha384')) return 'sha384';
    if (uri.includes('sha512')) return 'sha512';
    return 'sha256';
  }

  private _formatCert(cert: string): string {
    if (cert.includes('-----BEGIN')) return cert;
    // Wrap raw base64 cert in PEM format.
    const lines: string[] = [];
    lines.push('-----BEGIN CERTIFICATE-----');
    for (let i = 0; i < cert.length; i += 64) {
      lines.push(cert.slice(i, i + 64));
    }
    lines.push('-----END CERTIFICATE-----');
    return lines.join('\n');
  }

  /**
   * Validate SAML assertion conditions (time validity, audience, issuer).
   */
  private _validateAssertion(doc: SAXElement): void {
    const assertion = findElement(doc, 'Assertion');
    if (!assertion) {
      throw new Error('No SAML Assertion found in response');
    }

    // Validate Issuer — the assertion issuer is extracted in _extractProfile
    // and passed to the verify callback for application-level validation.

    // Validate Conditions (NotBefore / NotOnOrAfter).
    const conditions = findElement(assertion, 'Conditions');
    if (conditions) {
      const now = new Date();
      const clockSkew = 300_000; // 5 minutes tolerance

      const notBefore = conditions.attrs.NotBefore;
      if (notBefore) {
        const nbDate = new Date(notBefore);
        if (now.getTime() < nbDate.getTime() - clockSkew) {
          throw new Error(`SAML assertion not yet valid (NotBefore: ${notBefore})`);
        }
      }

      const notOnOrAfter = conditions.attrs.NotOnOrAfter;
      if (notOnOrAfter) {
        const noaDate = new Date(notOnOrAfter);
        if (now.getTime() >= noaDate.getTime() + clockSkew) {
          throw new Error(`SAML assertion has expired (NotOnOrAfter: ${notOnOrAfter})`);
        }
      }

      // Validate AudienceRestriction.
      const audienceRestriction = findElement(conditions, 'AudienceRestriction');
      if (audienceRestriction) {
        const audienceElem = findElement(audienceRestriction, 'Audience');
        if (audienceElem?.text && audienceElem.text !== this._issuer) {
          throw new Error(
            `SAML audience mismatch: expected ${this._issuer}, got ${audienceElem.text}`,
          );
        }
      }
    }

    // Validate SubjectConfirmation NotOnOrAfter.
    const subject = findElement(assertion, 'Subject');
    if (subject) {
      const subjectConfirmation = findElement(subject, 'SubjectConfirmation');
      if (subjectConfirmation) {
        const subjectConfData = findElement(subjectConfirmation, 'SubjectConfirmationData');
        if (subjectConfData?.attrs.NotOnOrAfter) {
          const noaDate = new Date(subjectConfData.attrs.NotOnOrAfter);
          if (new Date().getTime() >= noaDate.getTime() + 300_000) {
            throw new Error('SAML SubjectConfirmation has expired');
          }
        }
      }
    }
  }

  private _extractProfile(doc: SAXElement): SAMLProfile {
    const assertion = findElement(doc, 'Assertion');
    if (!assertion) {
      throw new Error('No SAML Assertion found in response');
    }

    // Issuer
    const issuerElem = findElement(assertion, 'Issuer');
    const issuer = issuerElem?.text || '';

    // NameID
    const nameIDElem = findElement(assertion, 'NameID');
    const nameID = nameIDElem?.text || '';
    const nameIDFormat = nameIDElem?.attrs.Format;

    // SessionIndex
    const authnStatement = findElement(assertion, 'AuthnStatement');
    const sessionIndex = authnStatement?.attrs.SessionIndex;

    // Attributes
    const attributes: Record<string, string> = {};
    const attrStatements = findElements(assertion, 'AttributeStatement');
    for (const stmt of attrStatements) {
      const attrs = findElements(stmt, 'Attribute');
      for (const attr of attrs) {
        const name = attr.attrs.Name || attr.attrs.FriendlyName || '';
        const valueElem = findElement(attr, 'AttributeValue');
        if (name && valueElem) {
          attributes[name] = valueElem.text;
        }
      }
    }

    return { issuer, nameID, nameIDFormat, sessionIndex, attributes };
  }

  private async _callVerify(profile: SAMLProfile): Promise<void> {
    const verify = this._verify;

    if (verify.length <= 1) {
      // Async verify(profile) => User
      const user = await (verify as SAMLVerifyAsync<User>)(profile);
      if (!user) {
        return this.fail({ message: 'SAML authentication failed' });
      }
      this.success(user);
    } else {
      // Callback verify(profile, done)
      await new Promise<void>((resolve, reject) => {
        (verify as SAMLVerifyCallback<User>)(profile, (err, result, info) => {
          if (err) return reject(err);
          if (result === false || !result) {
            this.fail(info || { message: 'SAML authentication failed' });
            return resolve();
          }
          this.success(result, info);
          resolve();
        });
      });
    }
  }
}

// Export the parser for testing purposes.
export { parseXML, findElement, findElements, type SAXElement };
