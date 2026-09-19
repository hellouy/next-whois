import { describe, it, expect } from "vitest";
import { analyzeWhois, detectPrivacyProxy } from "./common_parser";

describe("analyzeWhois — multilingual registrar / registrant extraction", () => {
  it("extracts Chinese (.cn CNNIC) registrar and registrant fields", async () => {
    const r = await analyzeWhois(`
Domain Name: example.cn
ROID: 20200101s10001s00000001-cn
Domain Status: clientTransferProhibited
注册者: 张伟
Sponsoring Registrar: 阿里云计算（万网）技术有限公司
Registrant Contact Email: 1234567890@qq.com
Registration Time: 2020-01-01 12:00:00
Expiration Time: 2025-01-01 12:00:00
Name Server: dns1.hichina.com
Name Server: dns2.hichina.com
`);
    expect(r.registrar).toBe("阿里云计算（万网）技术有限公司");
    expect(r.registrantName).toBe("张伟");
    expect(r.registrantEmail).toContain("@qq.com");
    expect(r.creationDate).not.toBe("Unknown");
    expect(r.expirationDate).not.toBe("Unknown");
  });

  it("extracts Chinese '注册商' / '注册者' / '电子邮件' keys", async () => {
    const r = await analyzeWhois(`
域名: example.cn
注册商: 北京新网数码信息技术有限公司
注册者: 测试公司
联系人邮箱: owner@example.cn
`);
    expect(r.registrar).toBe("北京新网数码信息技术有限公司");
    expect(r.registrantName).toBe("测试公司");
    expect(r.registrantEmail).toBe("owner@example.cn");
  });

  it("extracts Portuguese (.br Registro.br) registrador and titular", async () => {
    const r = await analyzeWhois(`
domain: example.com.br
registrador: REGISTRO.BR
owner: Empresa Exemplo LTDA
e-mail: owner@example.com.br
created: 2021-02-02
expires: 2024-02-02
`);
    expect(r.registrar).toBe("REGISTRO.BR");
    expect(r.registrantName).toBe("Empresa Exemplo LTDA");
    expect(r.registrantEmail).toBe("owner@example.com.br");
  });

  it("extracts Russian (.ru TCI) регистратор and организация", async () => {
    const r = await analyzeWhois(`
domain: example.ru
registrar: REGTIME-RU
организация: ООО "Пример"
e-mail: admin@example.ru
created: 2022-03-03
paid-till: 2025-03-03
`);
    expect(r.registrar).toBe("REGTIME-RU");
    expect(r.registrantOrganization).toContain("Пример");
  });

  it("extracts Vietnamese and Korean ccTLD registrant email variants", async () => {
    const r = await analyzeWhois(`
domain: example.vn
registrant: Some Person
registrant contact email: person@example.vn
created: 2020-05-05
`);
    expect(r.registrantName).toBe("Some Person");
    expect(r.registrantEmail).toBe("person@example.vn");
  });
});

describe("analyzeWhois — registrant privacy flag", () => {
  it("flags WhoisGuard-protected records", async () => {
    const r = await analyzeWhois(`
Domain Name: example.com
Registrar: Namecheap
Registrant Name: WhoisGuard Protected
Registrant Organization: WhoisGuard, Inc.
Privacy Service Address: Panama City, Panama
Registrant Email: 0123456789abcdef@whoisguard.com
`);
    expect(r.registrantPrivacy).toBe(true);
  });

  it("flags 'Withheld for Privacy Purposes' records", async () => {
    const r = await analyzeWhois(`
Domain Name: example.ca
Registrant Name: Withheld for Privacy Purposes
Registrant Email: privacy@example.ca
`);
    expect(r.registrantPrivacy).toBe(true);
  });

  it("flags Chinese privacy-proxy text (隐私保护)", async () => {
    const r = await analyzeWhois(`
域名: example.cn
注册者: 张三
联系人邮箱: xxxxx@privacy.com.cn
隐私保护: 该域名已开启隐私保护
`);
    expect(r.registrantPrivacy).toBe(true);
  });

  it("does NOT flag a registrar merely containing 'privacy' in its name", async () => {
    const r = await analyzeWhois(`
Domain Name: example.com
Registrar: Privacy Services LLC
Registrant Organization: Real Company Ltd
Registrant Email: ops@realcompany.com
`);
    expect(r.registrantPrivacy).toBeFalsy();
  });

  it("does NOT treat registrar contact/support fields as the registrar name", async () => {
    const cases = [
      "Registrar Customer Service: support@reg.example",
      "Registrar Support: help@reg.example",
      "Registrar Contact: John Doe",
    ];
    for (const line of cases) {
      const r = await analyzeWhois(`Domain Name: example.com\n${line}\n`);
      expect(r.registrar).toBe("Unknown");
    }
  });

  it("still extracts registrar from Sponsoring Registrar Organization (.id)", async () => {
    const r = await analyzeWhois(`
Domain Name: example.id
Sponsoring Registrar Organization: PT Registrasi Nama Domain
Sponsoring Registrar IANA ID: 1234
`);
    expect(r.registrar).toBe("PT Registrasi Nama Domain");
  });
});

describe("detectPrivacyProxy", () => {
  it("detects exact proxy markers only", () => {
    expect(detectPrivacyProxy("Protected by WhoIsGuard")).toBe(true);
    expect(detectPrivacyProxy("Withheld for Privacy Purposes")).toBe(true);
    expect(detectPrivacyProxy("PrivacyGuard")).toBe(true);
    expect(detectPrivacyProxy("该域名已开启隐私保护")).toBe(true);
  });

  it("ignores innocuous text", () => {
    expect(detectPrivacyProxy("Registrar: Namecheap, Inc.")).toBe(false);
    expect(detectPrivacyProxy("A privacy-focused company hosts this site")).toBe(false);
  });
});
