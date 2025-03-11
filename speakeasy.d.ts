declare module 'speakeasy' {
  interface GenerateSecretOptions {
    length?: number;
    name?: string;
    issuer?: string;
  }

  interface VerifyOptions {
    secret: string;
    encoding?: 'base32' | 'ascii' | 'hex';
    token: string;
    window?: number;
  }

  interface TOTPVerifyOptions extends VerifyOptions {
    time?: number;
  }

  interface Secret {
    ascii: string;
    hex: string;
    base32: string;
    otpauth_url?: string;
  }

  export function generateSecret(options?: GenerateSecretOptions): Secret;
  
  export namespace totp {
    function verify(options: TOTPVerifyOptions): boolean;
  }

  export namespace otpauthURL {
    function generate(options: {
      secret: string;
      label: string;
      issuer: string;
    }): string;
  }
}
