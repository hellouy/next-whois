declare module "@khmyznikov/pwa-install" {
  export default class PWAInstall extends HTMLElement {
    constructor();
  }
}

declare module "ocsp" {
  export const request: {
    generate(rawCert: Buffer, rawIssuer: Buffer): {
      data: Buffer;
      certID: any;
      id: Buffer;
      cert: any;
      issuer: any;
    };
  };
  export const utils: {
    parseResponse(buffer: Buffer): {
      value?: {
        tbsResponseData?: {
          responses?: { certStatus?: { type?: string } }[];
        };
      };
      start?: number;
      end?: number;
      certs?: any[];
      certsTbs?: any[];
    } | null;
    toDER(data: any, type: string): Buffer;
    toPEM(data: any, type: string): string;
  };
  export function check(options: { cert: any; issuer: any }, cb: (err: Error | null, res?: any) => void): void;
}

