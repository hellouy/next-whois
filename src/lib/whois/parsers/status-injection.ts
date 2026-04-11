/**
 * Synthetic status injection from raw WHOIS free-form text.
 *
 * Many ccTLD WHOIS servers express domain state as free-form text rather than
 * structured EPP status codes. This module detects those patterns and injects
 * synthetic status entries so downstream status detection works correctly.
 *
 * Four synthetic statuses are detected:
 *   registry-reserved    — domain held by registry, not available for registration
 *   registry-premium     — domain available but at premium / auction price
 *   registrationProhibited — domain cannot be registered by policy
 *   suspended            — domain was registered but has been suspended
 */

import { WhoisAnalyzeResult } from "@/lib/whois/types";

/**
 * Scan `data` (raw WHOIS text) for free-form phrases that indicate a special
 * domain state and push the appropriate synthetic status entries into
 * `result.status`.  Operates in-place; returns nothing.
 */
export function injectSyntheticStatuses(data: string, result: WhoisAnalyzeResult): void {
  const rawLow = data.toLowerCase();
  const hasStatusCode = (code: string) =>
    result.status.some((s) => typeof s.status === "string" && s.status.toLowerCase().includes(code));

  // ── RESERVED ──────────────────────────────────────────────────────────────
  // Domain is held by the registry and not available for public registration.
  const syntheticReserved =
    !hasStatusCode("reserved") &&
    (
      rawLow.includes("reserved name") ||
      rawLow.includes("this name is reserved") ||
      rawLow.includes("is a reserved name") ||
      rawLow.includes("domain is reserved") ||
      rawLow.includes("this domain is reserved") ||
      rawLow.includes("domain name is reserved") ||
      rawLow.includes("reserved by the registry") ||
      rawLow.includes("registry reserved") ||
      rawLow.includes("reserved-name") ||
      rawLow.includes("reserved domain") ||
      rawLow.includes("in the reserved list") ||
      rawLow.includes("on the reserved list") ||
      rawLow.includes("is in the reserved list") ||
      rawLow.includes("is on the reserved list") ||
      rawLow.includes("has been reserved") ||
      rawLow.includes("name is reserved") ||
      rawLow.includes("is reserved for") ||
      rawLow.includes("is reserved by") ||
      rawLow.includes("reserved for registry") ||
      rawLow.includes("reserved for the registry") ||
      rawLow.includes("registry has reserved") ||
      rawLow.includes("registry hold") ||
      rawLow.includes("held by the registry") ||
      rawLow.includes("domain is held") ||
      rawLow.includes("being held by") ||
      rawLow.includes("reserved for future use") ||
      rawLow.includes("reserved for official use") ||
      rawLow.includes("reserved for this registry") ||
      rawLow.includes("reserved at the registry") ||
      rawLow.includes("sunrise reserved") ||
      rawLow.includes("reserved for sunrise") ||
      rawLow.includes("reserved for landrush") ||
      rawLow.includes("landrush reserved") ||
      /\bstatus\s*:\s*reserved\b/.test(rawLow) ||
      /\bstate\s*:\s*reserved\b/.test(rawLow) ||
      /\bdomainstatus\s*:\s*reserved\b/.test(rawLow) ||
      rawLow.includes("reserviert") ||
      /\bstatus\s*:\s*reserviert\b/.test(rawLow) ||
      rawLow.includes("rezervovan") ||
      rawLow.includes("réservé") ||
      rawLow.includes("domaine réservé") ||
      rawLow.includes("domaine reserve") ||
      /\bstatus\s*:\s*r[eé]serv[eé]\b/.test(rawLow) ||
      rawLow.includes("reservado") ||
      rawLow.includes("dominio reservado") ||
      /\bestado\s*:\s*reservado\b/.test(rawLow) ||
      rawLow.includes("domínio reservado") ||
      /\bstatus\s*:\s*riservato\b/.test(rawLow) ||
      rawLow.includes("dominio riservato") ||
      /\bstate\s*:\s*reserverad\b/.test(rawLow) ||
      /\bstatus\s*:\s*reserverad\b/.test(rawLow) ||
      rawLow.includes("domännamnet är reserverat") ||
      /\bstatus\s*:\s*reservert\b/.test(rawLow) ||
      rawLow.includes("domenet er reservert") ||
      /\bstatus\s*:\s*reserveret\b/.test(rawLow) ||
      rawLow.includes("domænet er reserveret") ||
      /\bstatus\s*:\s*zarezerwowany\b/.test(rawLow) ||
      rawLow.includes("domena zarezerwowana") ||
      /\bstatus\s*:\s*gereserveerd\b/.test(rawLow) ||
      rawLow.includes("domein is gereserveerd") ||
      /\bstatus\s*:\s*varattu\b/.test(rawLow) ||
      rawLow.includes("verkkotunnus varattu") ||
      rawLow.includes("on varattu") ||
      /\bstatus\s*:\s*fenntartott\b/.test(rawLow) ||
      rawLow.includes("fenntartott tartomány") ||
      /\bstatus\s*:\s*rezervat\b/.test(rawLow) ||
      rawLow.includes("domeniu rezervat") ||
      /\bstatus\s*:\s*rezerve\b/.test(rawLow) ||
      rawLow.includes("alan adı rezerve") ||
      rawLow.includes("δεσμευμένο") ||
      rawLow.includes("зарезервирован") ||
      rawLow.includes("зарезервировано") ||
      rawLow.includes("зарезервирована") ||
      rawLow.includes("домен зарезервирован") ||
      rawLow.includes("заблокирован") ||
      rawLow.includes("зарезервовано") ||
      rawLow.includes("домен зарезервовано") ||
      rawLow.includes("予約済み") ||
      rawLow.includes("利用停止") ||
      rawLow.includes("登録停止") ||
      rawLow.includes("예약됨") ||
      rawLow.includes("예약된") ||
      rawLow.includes("예약된 도메인") ||
      rawLow.includes("محجوز") ||
      rawLow.includes("النطاق محجوز") ||
      rawLow.includes("שמור") ||
      rawLow.includes("הדומיין שמור") ||
      rawLow.includes("保留網域") ||
      rawLow.includes("已保留") ||
      rawLow.includes("保留域名") ||
      rawLow.includes("已被保留") ||
      rawLow.includes("注册局保留") ||
      rawLow.includes("保留中") ||
      rawLow.includes("该域名已保留") ||
      rawLow.includes("can not be registered online") ||
      rawLow.includes("cannot be registered online") ||
      rawLow.includes("not currently available for registration") ||
      rawLow.includes("currently not available for registration") ||
      rawLow.includes("reserved for future use by auda") ||
      rawLow.includes("reserved for auda") ||
      rawLow.includes("auda reserved") ||
      rawLow.includes("登録保留") ||
      rawLow.includes("登録審査中") ||
      rawLow.includes("jprs管理") ||
      rawLow.includes("jprs reserved") ||
      rawLow.includes("reserved by sgnic") ||
      rawLow.includes("allocated by sgnic") ||
      rawLow.includes("sgnic reserved") ||
      rawLow.includes("reserved by mynic") ||
      rawLow.includes("mynic reserved") ||
      rawLow.includes("ditempah") ||
      rawLow.includes("nama domain ditempah") ||
      rawLow.includes("dicadangkan") ||
      rawLow.includes("nama domain dicadangkan") ||
      rawLow.includes("pandi reserved") ||
      rawLow.includes("สงวนชื่อ") ||
      rawLow.includes("ถูกสงวน") ||
      rawLow.includes("thnic reserved") ||
      rawLow.includes("bảo lưu") ||
      rawLow.includes("đang bảo lưu") ||
      rawLow.includes("tên miền bảo lưu") ||
      rawLow.includes("vnnic reserved") ||
      rawLow.includes("nakareserbang") ||
      rawLow.includes("inireserba") ||
      rawLow.includes("not delegated") ||
      rawLow.includes("pending delegation") ||
      rawLow.includes("not yet delegated") ||
      rawLow.includes("pre-delegation") ||
      rawLow.includes("administrator hold") ||
      rawLow.includes("administrative hold") ||
      rawLow.includes("under registry administration") ||
      rawLow.includes("administered by the registry") ||
      rawLow.includes("managed by the registry") ||
      rawLow.includes("registry freeze") ||
      rawLow.includes("registry allocated") ||
      rawLow.includes("registry-allocated") ||
      /(?:^|\n)\s*reserved\s*(?:\n|$)/.test(rawLow)
    );

  if (syntheticReserved) {
    result.status.push({ status: "registry-reserved", url: "" });
  }

  // ── PREMIUM RESERVED ──────────────────────────────────────────────────────
  // Registry is holding this name for sale at a premium price.
  const syntheticPremiumReserved =
    !hasStatusCode("registry-premium") &&
    (
      rawLow.includes("premium domain") ||
      rawLow.includes("premium name") ||
      rawLow.includes("premium price") ||
      rawLow.includes("premium pricing") ||
      rawLow.includes("premium listing") ||
      rawLow.includes("registry premium") ||
      rawLow.includes("available at a premium") ||
      rawLow.includes("this is a premium") ||
      rawLow.includes("premium registration") ||
      rawLow.includes("early access program") ||
      rawLow.includes("early access pricing") ||
      rawLow.includes("early access period") ||
      rawLow.includes("available for purchase") ||
      rawLow.includes("available for sale") ||
      rawLow.includes("this name is for sale") ||
      rawLow.includes("domain is for sale") ||
      rawLow.includes("make an offer") ||
      rawLow.includes("aftermarket") ||
      rawLow.includes("reserve price") ||
      rawLow.includes("starting bid") ||
      rawLow.includes("minimum bid") ||
      rawLow.includes("please contact the registry") ||
      rawLow.includes("contact the registry to") ||
      rawLow.includes("contact the registry for") ||
      rawLow.includes("contact your registrar to") ||
      rawLow.includes("contact your registrar for") ||
      rawLow.includes("enquire about this domain") ||
      rawLow.includes("inquire about this domain") ||
      rawLow.includes("may be available for purchase") ||
      rawLow.includes("can be acquired") ||
      rawLow.includes("reach out to the registry")
    );

  if (syntheticPremiumReserved) {
    result.status.push({ status: "registry-premium", url: "" });
  }

  // ── PROHIBITED / BLOCKED ──────────────────────────────────────────────────
  // Domain string is policy-blocked and cannot be registered by anyone.
  const syntheticProhibited =
    !hasStatusCode("prohibited") &&
    !hasStatusCode("blocked") &&
    (
      rawLow.includes("registration is prohibited") ||
      rawLow.includes("registration prohibited") ||
      rawLow.includes("cannot be registered") ||
      rawLow.includes("registration not possible") ||
      rawLow.includes("registration not available") ||
      rawLow.includes("not available for registration") ||
      rawLow.includes("not eligible for registration") ||
      rawLow.includes("not open for registration") ||
      rawLow.includes("not open for general registration") ||
      rawLow.includes("not open to general registrations") ||
      rawLow.includes("not currently open for registration") ||
      rawLow.includes("not available for public registration") ||
      rawLow.includes("not permitted to register") ||
      rawLow.includes("registration is not permitted") ||
      rawLow.includes("registrations are not permitted") ||
      rawLow.includes("registrations not permitted") ||
      rawLow.includes("not accepting registrations") ||
      rawLow.includes("registrations not accepted") ||
      rawLow.includes("no registrations are accepted") ||
      rawLow.includes("does not accept registrations") ||
      rawLow.includes("cannot be publicly registered") ||
      rawLow.includes("prohibited string") ||
      rawLow.includes("prohibited by policy") ||
      rawLow.includes("policy prohibited") ||
      rawLow.includes("not available for public use") ||
      rawLow.includes("registrar banned") ||
      rawLow.includes("registry banned") ||
      rawLow.includes("blacklisted") ||
      rawLow.includes("禁止注册") ||
      rawLow.includes("不开放注册") ||
      rawLow.includes("不可注册") ||
      rawLow.includes("禁止使用") ||
      rawLow.includes("запрещена регистрация") ||
      rawLow.includes("регистрация запрещена") ||
      rawLow.includes("реєстрація заборонена") ||
      /\bstatus\s*:\s*vietato\b/.test(rawLow) ||
      rawLow.includes("registrazione vietata") ||
      rawLow.includes("登録不可") ||
      rawLow.includes("登録制限") ||
      rawLow.includes("등록불가") ||
      rawLow.includes("등록 금지") ||
      rawLow.includes("محظور") ||
      rawLow.includes("التسجيل محظور") ||
      rawLow.includes("登録できません") ||
      rawLow.includes("利用できません") ||
      rawLow.includes("bị cấm đăng ký") ||
      rawLow.includes("không được đăng ký") ||
      rawLow.includes("cấm đăng ký") ||
      rawLow.includes("tidak dapat didaftarkan") ||
      rawLow.includes("dilarang didaftarkan") ||
      rawLow.includes("tidak tersedia untuk registrasi") ||
      rawLow.includes("ห้ามจดทะเบียน") ||
      rawLow.includes("ไม่สามารถจดทะเบียน") ||
      rawLow.includes("prohibited by sgnic") ||
      rawLow.includes("not eligible for .sg") ||
      rawLow.includes("tidak layak didaftarkan") ||
      rawLow.includes("tidak boleh didaftarkan") ||
      rawLow.includes("bawal irehistro") ||
      rawLow.includes("hindi maaaring irehistro") ||
      rawLow.includes("לא ניתן לרשום") ||
      rawLow.includes("רישום אסור") ||
      rawLow.includes("δεν επιτρέπεται η εγγραφή") ||
      /\bblocked\s+by\s+(?:registry|registrar)\b/.test(rawLow) ||
      /\bregistration\s+blocked\b/.test(rawLow)
    );

  if (syntheticProhibited) {
    result.status.push({ status: "registrationProhibited", url: "" });
  }

  // ── SUSPENDED / HOLD ──────────────────────────────────────────────────────
  // Domain was registered but has been suspended by the registry or registrar.
  const syntheticSuspended =
    !hasStatusCode("suspended") &&
    !hasStatusCode("hold") &&
    (
      rawLow.includes("suspended by registry") ||
      rawLow.includes("suspended by registrar") ||
      rawLow.includes("registry-suspended") ||
      rawLow.includes("domain is suspended") ||
      rawLow.includes("domain suspended") ||
      rawLow.includes("domain has been suspended") ||
      rawLow.includes("account suspended") ||
      rawLow.includes("abuse suspension") ||
      rawLow.includes("abuse hold") ||
      rawLow.includes("fraud hold") ||
      rawLow.includes("compliance hold") ||
      rawLow.includes("billing suspension") ||
      rawLow.includes("domain is on hold") ||
      rawLow.includes("registrar hold") ||
      rawLow.includes("gesperrt") ||
      rawLow.includes("suspendido") ||
      rawLow.includes("suspendu") ||
      rawLow.includes("suspenso") ||
      rawLow.includes("domínio suspenso") ||
      /\bstatus\s*:\s*sospeso\b/.test(rawLow) ||
      rawLow.includes("dominio sospeso") ||
      rawLow.includes("opgeschort") ||
      rawLow.includes("domein opgeschort") ||
      rawLow.includes("zawieszony") ||
      rawLow.includes("domena zawieszona") ||
      rawLow.includes("keskeytetty") ||
      rawLow.includes("приостановлен") ||
      rawLow.includes("приостановлено") ||
      rawLow.includes("домен заблокирован") ||
      rawLow.includes("призупинено") ||
      rawLow.includes("停止中") ||
      rawLow.includes("利用停止") ||
      rawLow.includes("정지됨") ||
      rawLow.includes("사용 정지") ||
      rawLow.includes("موقوف") ||
      rawLow.includes("معلق") ||
      rawLow.includes("已暂停") ||
      rawLow.includes("域名暂停") ||
      rawLow.includes("已停用") ||
      rawLow.includes("暫停使用") ||
      /(?:^|\n)\s*suspended\s*(?:\n|$)/.test(rawLow)
    );

  if (syntheticSuspended) {
    result.status.push({ status: "suspended", url: "" });
  }
}
