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
  cert?: string;
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
  private _cert?: string;
  private _verify: SAMLVerifyFn<User>;

  constructor(options: SAMLStrategyOptions, verify: SAMLVerifyFn<User>) {
    super();
    this._entryPoint = options.entryPoint;
    this._issuer = options.issuer;
    this._callbackURL = options.callbackURL;
    this._cert = options.cert;
    this._verify = verify;
  }

  async authenticate(req: AegisRequest): Promise<void> {
    const body = (req as unknown as { body?: Record<string, string> }).body;

    if (body?.SAMLResponse) {
      return this._handleResponse(body.SAMLResponse);
    }

    // Initiate SAML flow: redirect to IdP.
    return this._redirectToIdP();
  }

  private _redirectToIdP(): void {
    const samlRequest = Buffer.from(
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_${Date.now()}" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${this._callbackURL}" ` +
        `Issuer="${this._issuer}" />`,
    ).toString('base64');

    const params = new URLSearchParams({ SAMLRequest: samlRequest });
    this.redirect(`${this._entryPoint}?${params.toString()}`);
  }

  private async _handleResponse(samlResponse: string): Promise<void> {
    try {
      const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
      const doc = parseXML(xml);

      const profile = this._extractProfile(doc);

      await this._callVerify(profile);
    } catch (err) {
      this.error(err as Error);
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
