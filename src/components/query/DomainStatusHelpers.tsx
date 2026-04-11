import React from "react";
import { cn } from "@/lib/utils";
import {
  RiForbidLine,
  RiLockLine,
  RiPauseCircleLine,
  RiScalesLine,
  RiLoopLeftLine,
  RiDeleteBin2Line,
  RiCheckLine,
} from "@remixicon/react";
import { WhoisAnalyzeResult } from "@/lib/whois/types";
import { RegistrationStatusType } from "@/lib/domain-status-types";

const STATUS_LABELS: Record<RegistrationStatusType, { zh: string; en: string }> = {
  registered: { zh: "已注册", en: "Registered" },
  available: { zh: "未注册", en: "Available" },
  reserved: { zh: "保留域名", en: "Reserved" },
  prohibited: { zh: "禁止注册", en: "Prohibited" },
  hold: { zh: "暂停", en: "On Hold" },
  dispute: { zh: "争议中", en: "In Dispute" },
  redemption: { zh: "赎回期", en: "Redemption" },
  "pending-delete": { zh: "待删除", en: "Pending Delete" },
};

export function getDomainRegistrationStatus(
  result: WhoisAnalyzeResult,
  locale = "en",
): {
  type: RegistrationStatusType;
  label: string;
  color: string;
  dotColor: string;
  isPremiumReserved: boolean;
} {
  const isZh = locale.startsWith("zh");

  // EPP lock statuses that contain "prohibited" in their name but are NOT
  // about registration prohibition — they protect already-registered domains.
  const EPP_PROHIBITED_LOCK_STATUSES = new Set([
    "clientdeleteprohibited",
    "clienttransferprohibited",
    "clientrenewprohibited",
    "clientupdateprohibited",
    "serverdeleteprohibited",
    "servertransferprohibited",
    "serverrenewprohibited",
    "serverupdateprohibited",
    // hyphenated / space variants used by some ccTLDs
    "client-delete-prohibited",
    "client-transfer-prohibited",
    "client-renew-prohibited",
    "client-update-prohibited",
    "server-delete-prohibited",
    "server-transfer-prohibited",
    "server-renew-prohibited",
    "server-update-prohibited",
  ]);

  const allStatusCodes = result.status.map((s) => String(s.status ?? "").toLowerCase().trim());
  const allStatusText = allStatusCodes.join(" ");

  // Build a separate text excluding EPP lock statuses for the prohibit check
  // so that "clientTransferProhibited" / "client transfer prohibited" /
  // "client-transfer-prohibited" do not trigger "禁止注册".
  // We check THREE forms of each code: the raw first-word, the full hyphenated
  // string (some ccTLDs emit "client-delete-prohibited"), and the concatenated
  // no-separator form (TWNIC WHOIS emits "client delete prohibited" with spaces).
  const prohibitCheckText = allStatusCodes
    .filter((s) => {
      const firstWord = s.split(/\s+/)[0];            // "client" from "client delete prohibited"
      const noSep = s.replace(/[\s_\-]/g, "");        // "clientdeleteprohibited"
      return (
        !EPP_PROHIBITED_LOCK_STATUSES.has(firstWord) &&
        !EPP_PROHIBITED_LOCK_STATUSES.has(noSep)
      );
    })
    .join(" ");

  // ── Raw content scan (safety net for RDAP and exotic ccTLD WHOIS formats) ───
  // Some registries embed state as free text in WHOIS/RDAP rather than EPP
  // codes. Scan the raw content with specific phrases to capture these signals.
  const rawContent = [
    typeof result.rawWhoisContent === "string" ? result.rawWhoisContent : "",
    result.rawRdapContent
      ? typeof result.rawRdapContent === "string"
        ? result.rawRdapContent
        : JSON.stringify(result.rawRdapContent)
      : "",
  ]
    .join("\n")
    .toLowerCase();

  // ── RESERVED — mirrors common_parser.ts syntheticReserved exactly ───────────
  const rawHasReserved =
    // English free-text phrases
    rawContent.includes("reserved name") ||
    rawContent.includes("this name is reserved") ||
    rawContent.includes("is a reserved name") ||
    rawContent.includes("domain is reserved") ||
    rawContent.includes("this domain is reserved") ||
    rawContent.includes("domain name is reserved") ||
    rawContent.includes("reserved by the registry") ||
    rawContent.includes("registry reserved") ||
    rawContent.includes("reserved-name") ||
    rawContent.includes("reserved domain") ||
    rawContent.includes("in the reserved list") ||
    rawContent.includes("on the reserved list") ||
    rawContent.includes("is in the reserved list") ||
    rawContent.includes("is on the reserved list") ||
    rawContent.includes("has been reserved") ||
    rawContent.includes("name is reserved") ||
    rawContent.includes("is reserved for") ||
    rawContent.includes("is reserved by") ||
    rawContent.includes("reserved for registry") ||
    rawContent.includes("reserved for the registry") ||
    rawContent.includes("registry has reserved") ||
    rawContent.includes("registry hold") ||
    rawContent.includes("held by the registry") ||
    rawContent.includes("domain is held") ||
    rawContent.includes("being held by") ||
    rawContent.includes("reserved for future use") ||
    rawContent.includes("reserved for official use") ||
    rawContent.includes("reserved for this registry") ||
    rawContent.includes("reserved at the registry") ||
    rawContent.includes("sunrise reserved") ||
    rawContent.includes("reserved for sunrise") ||
    rawContent.includes("reserved for landrush") ||
    rawContent.includes("landrush reserved") ||
    // Withheld — Donuts, Radix, ICM, Minds + Machines new gTLDs
    rawContent.includes("withheld") ||
    rawContent.includes("withheld by registry") ||
    rawContent.includes("withheld for registry") ||
    rawContent.includes("registry withheld") ||
    rawContent.includes("name withheld") ||
    rawContent.includes("domain withheld") ||
    /\bstatus\s*:\s*withheld\b/.test(rawContent) ||
    // IANA / ICANN delegations — "not delegated" / "not assigned"
    rawContent.includes("not delegated") ||
    rawContent.includes("not-delegated") ||
    rawContent.includes("not assigned") ||
    rawContent.includes("iana reserved") ||
    rawContent.includes("iana hold") ||
    rawContent.includes("blocked by iana") ||
    rawContent.includes("has not been delegated") ||
    rawContent.includes("this tld has not") ||
    /\bstatus\s*:\s*not.delegated\b/.test(rawContent) ||
    // Available only by specific request (some ccTLDs, e.g. .uk)
    rawContent.includes("available-by-request") ||
    rawContent.includes("available by request") ||
    rawContent.includes("registration by request only") ||
    rawContent.includes("available to specific registrants") ||
    rawContent.includes("restricted to qualified") ||
    // "Allocated" (RIPE/RIR context, some country ccTLDs)
    /\bstatus\s*:\s*allocated\b/.test(rawContent) ||
    // Blocked by registry (for reserved/sensitive strings — not abuse block)
    /\bstatus\s*:\s*blocked\b/.test(rawContent) ||
    rawContent.includes("blocked for registration") ||
    rawContent.includes("registry block") ||
    // RDAP "remarks" text: "This domain has not been delegated"
    rawContent.includes("not been delegated") ||
    // Structured field patterns (EURID .eu, IIS .se/.nu, Donuts, CentralNic, CIRA, etc.)
    /\bstatus\s*:\s*reserved\b/.test(rawContent) ||
    /\bstate\s*:\s*reserved\b/.test(rawContent) ||
    /\bdomainstatus\s*:\s*reserved\b/.test(rawContent) ||
    // German (DENIC .de): "% Status: reserviert"
    rawContent.includes("reserviert") ||
    /\bstatus\s*:\s*reserviert\b/.test(rawContent) ||
    // Czech/Slovak (CZ.NIC .cz .sk): "rezervovan: ano"
    rawContent.includes("rezervovan") ||
    // French ccTLD (AFNIC .fr .re .pm .tf .wf .yt)
    rawContent.includes("réservé") ||
    rawContent.includes("domaine réservé") ||
    rawContent.includes("domaine reserve") ||
    /\bstatus\s*:\s*r[eé]serv[eé]\b/.test(rawContent) ||
    // Spanish ccTLD (.es, .ar, .mx, .co, .cl, .pe, .uy, etc.)
    rawContent.includes("reservado") ||
    rawContent.includes("dominio reservado") ||
    /\bestado\s*:\s*reservado\b/.test(rawContent) ||
    // Portuguese (.pt / .br)
    rawContent.includes("domínio reservado") ||
    // Italian (NIC.it .it): RISERVATO
    /\bstatus\s*:\s*riservato\b/.test(rawContent) ||
    rawContent.includes("dominio riservato") ||
    // Swedish (IIS .se .nu): "state: reserverad"
    /\bstate\s*:\s*reserverad\b/.test(rawContent) ||
    /\bstatus\s*:\s*reserverad\b/.test(rawContent) ||
    rawContent.includes("domännamnet är reserverat") ||
    // Norwegian (Norid .no)
    /\bstatus\s*:\s*reservert\b/.test(rawContent) ||
    rawContent.includes("domenet er reservert") ||
    // Danish (DK Hostmaster .dk)
    /\bstatus\s*:\s*reserveret\b/.test(rawContent) ||
    rawContent.includes("domænet er reserveret") ||
    // Polish (DNS Polska / NASK .pl)
    /\bstatus\s*:\s*zarezerwowany\b/.test(rawContent) ||
    rawContent.includes("domena zarezerwowana") ||
    // Dutch (SIDN .nl)
    /\bstatus\s*:\s*gereserveerd\b/.test(rawContent) ||
    rawContent.includes("domein is gereserveerd") ||
    // Finnish (Traficom .fi): "varattu"
    /\bstatus\s*:\s*varattu\b/.test(rawContent) ||
    rawContent.includes("verkkotunnus varattu") ||
    rawContent.includes("on varattu") ||
    // Hungarian (.hu): "fenntartott"
    /\bstatus\s*:\s*fenntartott\b/.test(rawContent) ||
    rawContent.includes("fenntartott tartomány") ||
    // Romanian (RoTLD .ro): "rezervat"
    /\bstatus\s*:\s*rezervat\b/.test(rawContent) ||
    rawContent.includes("domeniu rezervat") ||
    // Turkish (NIC.TR .tr): "rezerve"
    /\bstatus\s*:\s*rezerve\b/.test(rawContent) ||
    rawContent.includes("alan adı rezerve") ||
    // Greek (ICS.FORTH .gr)
    rawContent.includes("δεσμευμένο") ||
    rawContent.includes("δεσμεύτηκε") ||
    // Bulgarian (.bg)
    rawContent.includes("резервиран") ||
    // Serbian / Bosnian / Croatian (.rs / .ba / .hr)
    rawContent.includes("rezervisano") ||
    rawContent.includes("rezervirano") ||
    // Latvian (NIC.lv .lv)
    rawContent.includes("rezervēts") ||
    // Lithuanian (DOMREG .lt)
    rawContent.includes("rezervuotas") ||
    // Estonian (EIS .ee)
    rawContent.includes("reserveeritud") ||
    // Slovak (.sk)
    rawContent.includes("rezervovaný") ||
    // Russian (.ru / .рф) — non-Latin, safe direct includes
    rawContent.includes("зарезервирован") ||
    rawContent.includes("зарезервировано") ||
    rawContent.includes("зарезервирована") ||
    rawContent.includes("домен зарезервирован") ||
    rawContent.includes("заблокирован") ||
    // Ukrainian (.ua)
    rawContent.includes("зарезервовано") ||
    rawContent.includes("домен зарезервовано") ||
    // Japanese (.jp — JPRS): bilingual WHOIS
    rawContent.includes("予約済み") ||
    rawContent.includes("利用停止") ||
    rawContent.includes("登録停止") ||
    // Korean (.kr — KRNIC)
    rawContent.includes("예약됨") ||
    rawContent.includes("예약된") ||
    rawContent.includes("예약된 도메인") ||
    // Arabic ccTLDs (.sa / .ae / .eg / .iq / .ly)
    rawContent.includes("محجوز") ||
    rawContent.includes("النطاق محجوز") ||
    rawContent.includes("مخصص") ||
    // Hebrew (.il — ISOC-IL)
    rawContent.includes("שמור") ||
    rawContent.includes("הדומיין שמור") ||
    // Traditional Chinese (.tw / .hk)
    rawContent.includes("保留網域") ||
    rawContent.includes("已保留") ||
    // Simplified Chinese (CNNIC, TELE-INFO, ZDNS)
    rawContent.includes("保留域名") ||
    rawContent.includes("已被保留") ||
    rawContent.includes("注册局保留") ||
    rawContent.includes("保留中") ||
    rawContent.includes("该域名已保留") ||
    rawContent.includes("域名已锁定") ||
    // CNNIC (.cn) reserved domains — registry holds name, offline only
    // Response text: "the Domain Name you apply can not be registered online.
    //                 Please consult your Domain Name registrar"
    rawContent.includes("can not be registered online") ||
    rawContent.includes("cannot be registered online") ||
    // Standalone "reserved" on its own line (TWNIC / NZRS)
    /(?:^|\n)\s*reserved\s*(?:\n|$)/.test(rawContent);

  // ── PREMIUM RESERVED — mirrors common_parser.ts syntheticPremiumReserved ────
  const rawHasPremiumReserved =
    rawContent.includes("premium domain") ||
    rawContent.includes("premium name") ||
    rawContent.includes("premium price") ||
    rawContent.includes("premium pricing") ||
    rawContent.includes("premium listing") ||
    rawContent.includes("registry premium") ||
    rawContent.includes("available at a premium") ||
    rawContent.includes("this is a premium") ||
    rawContent.includes("premium registration") ||
    rawContent.includes("early access program") ||
    rawContent.includes("early access pricing") ||
    rawContent.includes("early access period") ||
    rawContent.includes("available for purchase") ||
    rawContent.includes("available for sale") ||
    rawContent.includes("this name is for sale") ||
    rawContent.includes("domain is for sale") ||
    rawContent.includes("make an offer") ||
    rawContent.includes("aftermarket") ||
    rawContent.includes("reserve price") ||
    rawContent.includes("starting bid") ||
    rawContent.includes("minimum bid") ||
    rawContent.includes("please contact the registry") ||
    rawContent.includes("contact the registry to") ||
    rawContent.includes("contact the registry for") ||
    rawContent.includes("contact your registrar to") ||
    rawContent.includes("contact your registrar for") ||
    rawContent.includes("enquire about this domain") ||
    rawContent.includes("inquire about this domain") ||
    rawContent.includes("may be available for purchase") ||
    rawContent.includes("can be acquired") ||
    rawContent.includes("reach out to the registry");

  // ── PROHIBITED — mirrors common_parser.ts syntheticProhibited ────────────
  const rawHasProhibited =
    rawContent.includes("registration is prohibited") ||
    rawContent.includes("registration prohibited") ||
    rawContent.includes("cannot be registered") ||
    rawContent.includes("registration not possible") ||
    rawContent.includes("registration not available") ||
    rawContent.includes("not available for registration") ||
    rawContent.includes("not eligible for registration") ||
    rawContent.includes("not open for registration") ||
    rawContent.includes("not open for general registration") ||
    rawContent.includes("not open to general registrations") ||
    rawContent.includes("not currently open for registration") ||
    rawContent.includes("not available for public registration") ||
    rawContent.includes("not permitted to register") ||
    rawContent.includes("registration is not permitted") ||
    rawContent.includes("registrations are not permitted") ||
    rawContent.includes("registrations not permitted") ||
    rawContent.includes("not accepting registrations") ||
    rawContent.includes("registrations not accepted") ||
    rawContent.includes("no registrations are accepted") ||
    rawContent.includes("does not accept registrations") ||
    rawContent.includes("cannot be publicly registered") ||
    rawContent.includes("prohibited string") ||
    rawContent.includes("prohibited by policy") ||
    rawContent.includes("policy prohibited") ||
    rawContent.includes("not available for public use") ||
    rawContent.includes("registrar banned") ||
    rawContent.includes("registry banned") ||
    rawContent.includes("blacklisted") ||
    // Additional English patterns
    rawContent.includes("registration is blocked") ||
    rawContent.includes("domain is blocked") ||
    rawContent.includes("name is blocked") ||
    rawContent.includes("blackholed") ||
    rawContent.includes("registration disallowed") ||
    rawContent.includes("registration is disallowed") ||
    rawContent.includes("registrations are disallowed") ||
    rawContent.includes("registration has been blocked") ||
    rawContent.includes("domain name cannot be registered") ||
    rawContent.includes("name cannot be registered") ||
    rawContent.includes("does not allow registrations") ||
    rawContent.includes("registry does not allow") ||
    rawContent.includes("ineligible for registration") ||
    rawContent.includes("registration ineligible") ||
    rawContent.includes("this string is prohibited") ||
    rawContent.includes("this label is prohibited") ||
    rawContent.includes("this domain cannot be registered") ||
    rawContent.includes("cannot register this domain") ||
    rawContent.includes("registration of this name is not") ||
    rawContent.includes("not available at this time") ||
    rawContent.includes("agency forbidden") ||
    rawContent.includes("forbidden by") ||
    /\bstatus\s*:\s*prohibited\b/.test(rawContent) ||
    /\bstatus\s*:\s*forbidden\b/.test(rawContent) ||
    /\bstatus\s*:\s*blocked\-prohibited\b/.test(rawContent) ||
    // Simplified / Traditional Chinese
    rawContent.includes("禁止注册") ||
    rawContent.includes("不开放注册") ||
    rawContent.includes("不可注册") ||
    rawContent.includes("禁止使用") ||
    rawContent.includes("禁止域名") ||
    rawContent.includes("限制注册") ||
    rawContent.includes("禁止") && rawContent.includes("注册") ||
    // Russian / Ukrainian
    rawContent.includes("запрещена регистрация") ||
    rawContent.includes("регистрация запрещена") ||
    rawContent.includes("реєстрація заборонена") ||
    rawContent.includes("реєстрація не дозволена") ||
    rawContent.includes("регистрация недоступна") ||
    // German (.de / .at / .ch)
    rawContent.includes("registrierung nicht möglich") ||
    rawContent.includes("nicht registrierbar") ||
    rawContent.includes("gesperrte zeichenfolge") ||
    /\bstatus\s*:\s*verboten\b/.test(rawContent) ||
    // French
    rawContent.includes("enregistrement interdit") ||
    rawContent.includes("non disponible à l'enregistrement") ||
    // Spanish
    rawContent.includes("registro prohibido") ||
    rawContent.includes("no se puede registrar") ||
    rawContent.includes("no disponible para registro") ||
    // Italian
    /\bstatus\s*:\s*vietato\b/.test(rawContent) ||
    rawContent.includes("registrazione vietata") ||
    rawContent.includes("non registrabile") ||
    // Portuguese
    rawContent.includes("registro não permitido") ||
    rawContent.includes("domínio proibido") ||
    // Dutch
    rawContent.includes("registratie niet mogelijk") ||
    rawContent.includes("niet registreerbaar") ||
    // Polish
    rawContent.includes("rejestracja zabroniona") ||
    rawContent.includes("niedostępne do rejestracji") ||
    // Japanese
    rawContent.includes("登録不可") ||
    rawContent.includes("登録制限") ||
    rawContent.includes("利用不可") ||
    rawContent.includes("申請不可") ||
    // Korean
    rawContent.includes("등록불가") ||
    rawContent.includes("등록 금지") ||
    rawContent.includes("등록 불가능") ||
    // Arabic
    rawContent.includes("محظور") ||
    rawContent.includes("التسجيل محظور") ||
    rawContent.includes("غير متاح للتسجيل") ||
    // Hebrew
    rawContent.includes("אסור לרישום") ||
    rawContent.includes("חסום לרישום") ||
    // Turkish
    rawContent.includes("kayıt yasak") ||
    rawContent.includes("tescil edilemez") ||
    /\bblocked\s+by\s+(?:registry|registrar)\b/.test(rawContent) ||
    /\bregistration\s+blocked\b/.test(rawContent);

  // ── SUSPENDED / HOLD ─────────────────────────────────────────────────────
  const rawHasSuspended =
    rawContent.includes("suspended by registry") ||
    rawContent.includes("suspended by registrar") ||
    rawContent.includes("registry-suspended") ||
    rawContent.includes("domain is suspended") ||
    rawContent.includes("domain suspended") ||
    rawContent.includes("domain has been suspended") ||
    rawContent.includes("account suspended") ||
    rawContent.includes("abuse suspension") ||
    rawContent.includes("abuse hold") ||
    rawContent.includes("fraud hold") ||
    rawContent.includes("compliance hold") ||
    rawContent.includes("billing suspension") ||
    rawContent.includes("billing hold") ||
    rawContent.includes("payment hold") ||
    rawContent.includes("domain is on hold") ||
    rawContent.includes("domain on hold") ||
    rawContent.includes("placed on hold") ||
    rawContent.includes("put on hold") ||
    rawContent.includes("account on hold") ||
    rawContent.includes("account hold") ||
    rawContent.includes("registrar hold") ||
    rawContent.includes("agency hold") ||
    rawContent.includes("legal hold") ||
    rawContent.includes("judicial hold") ||
    rawContent.includes("government hold") ||
    rawContent.includes("seized by") ||
    rawContent.includes("domain seized") ||
    rawContent.includes("domain has been seized") ||
    rawContent.includes("confiscated by") ||
    rawContent.includes("domain confiscated") ||
    rawContent.includes("law enforcement hold") ||
    rawContent.includes("enforcement hold") ||
    rawContent.includes("frozen by") ||
    rawContent.includes("domain frozen") ||
    rawContent.includes("domain has been frozen") ||
    rawContent.includes("domain is frozen") ||
    rawContent.includes("suspended for") ||
    rawContent.includes("suspended due to") ||
    rawContent.includes("temporarily suspended") ||
    rawContent.includes("domain is temporarily") ||
    rawContent.includes("temporarily unavailable") ||
    rawContent.includes("domain is inactive") ||
    /\bstatus\s*:\s*(?:hold|on-hold|onhold|inactive)\b/.test(rawContent) ||
    // German (.de / .at / .ch)
    rawContent.includes("gesperrt") ||
    rawContent.includes("sperrung") ||
    rawContent.includes("domain gesperrt") ||
    rawContent.includes("beschlagnahmt") ||
    rawContent.includes("eingefroren") ||
    // Spanish (.es / .ar / .mx / ...)
    rawContent.includes("suspendido") ||
    rawContent.includes("dominio suspendido") ||
    rawContent.includes("en espera") ||
    rawContent.includes("confiscado") ||
    rawContent.includes("embargado") ||
    // French (.fr / .be / .ch / ...)
    rawContent.includes("suspendu") ||
    rawContent.includes("domaine suspendu") ||
    rawContent.includes("bloqué") ||
    rawContent.includes("saisi") ||
    rawContent.includes("gelé") ||
    // Portuguese (.pt / .br)
    rawContent.includes("suspenso") ||
    rawContent.includes("domínio suspenso") ||
    rawContent.includes("congelado") ||
    rawContent.includes("apreendido") ||
    // Italian (NIC.it .it)
    /\bstatus\s*:\s*sospeso\b/.test(rawContent) ||
    rawContent.includes("dominio sospeso") ||
    rawContent.includes("bloccato") ||
    rawContent.includes("sequestrato") ||
    // Dutch (.nl)
    rawContent.includes("opgeschort") ||
    rawContent.includes("domein opgeschort") ||
    rawContent.includes("bevroren") ||
    rawContent.includes("in beslag") ||
    // Polish (.pl)
    rawContent.includes("zawieszony") ||
    rawContent.includes("domena zawieszona") ||
    rawContent.includes("zablokowany") ||
    // Finnish (.fi)
    rawContent.includes("keskeytetty") ||
    rawContent.includes("jäädytetty") ||
    // Swedish (.se)
    rawContent.includes("spärrad") ||
    rawContent.includes("inaktiv") ||
    // Norwegian (.no)
    rawContent.includes("suspendert") ||
    // Danish (.dk)
    rawContent.includes("suspenderet") ||
    rawContent.includes("deaktiveret") ||
    // Romanian (.ro)
    rawContent.includes("suspendat") ||
    // Hungarian (.hu)
    rawContent.includes("felfüggesztett") ||
    // Turkish (.tr)
    rawContent.includes("askıya alındı") ||
    rawContent.includes("donduruldu") ||
    // Greek (.gr)
    rawContent.includes("ανεσταλμένο") ||
    rawContent.includes("αδρανές") ||
    // Russian (.ru / .рф)
    rawContent.includes("приостановлен") ||
    rawContent.includes("приостановлено") ||
    rawContent.includes("домен заблокирован") ||
    rawContent.includes("изъят") ||
    rawContent.includes("заморожен") ||
    // Ukrainian (.ua)
    rawContent.includes("призупинено") ||
    rawContent.includes("заморожено") ||
    // Japanese (.jp)
    rawContent.includes("停止中") ||
    rawContent.includes("利用停止") ||
    rawContent.includes("凍結") ||
    rawContent.includes("差し押さえ") ||
    // Korean (.kr)
    rawContent.includes("정지됨") ||
    rawContent.includes("사용 정지") ||
    rawContent.includes("동결") ||
    // Arabic
    rawContent.includes("موقوف") ||
    rawContent.includes("معلق") ||
    rawContent.includes("مجمد") ||
    rawContent.includes("مضبوط") ||
    // Hebrew
    rawContent.includes("מושעה") ||
    rawContent.includes("קפוא") ||
    // Chinese (Simplified)
    rawContent.includes("已暂停") ||
    rawContent.includes("域名暂停") ||
    rawContent.includes("已停用") ||
    rawContent.includes("暂停使用") ||
    rawContent.includes("已冻结") ||
    rawContent.includes("冻结域名") ||
    rawContent.includes("被扣押") ||
    rawContent.includes("被没收") ||
    /(?:^|\n)\s*suspended\s*(?:\n|$)/.test(rawContent);

  // ── DISPUTE ─────────────────────────────────────────────────────────────────
  const rawHasDispute =
    // UDRP (Uniform Domain-Name Dispute-Resolution Policy) — most common
    rawContent.includes("udrp") ||
    rawContent.includes("uniform domain-name dispute") ||
    rawContent.includes("udrp proceeding") ||
    rawContent.includes("udrp complaint") ||
    rawContent.includes("udrp-lock") ||
    rawContent.includes("udrp lock") ||
    rawContent.includes("locked-udrp") ||
    rawContent.includes("locked for udrp") ||
    rawContent.includes("locked during udrp") ||
    rawContent.includes("pending udrp") ||
    rawContent.includes("udrp transfer") ||
    rawContent.includes("udrp decision") ||
    // General dispute
    rawContent.includes("domain dispute") ||
    rawContent.includes("name dispute") ||
    rawContent.includes("in dispute") ||
    rawContent.includes("under dispute") ||
    rawContent.includes("dispute in progress") ||
    rawContent.includes("dispute pending") ||
    rawContent.includes("subject to dispute") ||
    rawContent.includes("currently disputed") ||
    rawContent.includes("domain conflict") ||
    // DRP / ADR variants (EU/ICANN alternative dispute resolution)
    rawContent.includes("adr proceeding") ||
    rawContent.includes("alternative dispute") ||
    rawContent.includes("domain resolution") ||
    rawContent.includes("drp proceeding") ||
    rawContent.includes("icann drp") ||
    // Trademark / legal dispute
    rawContent.includes("trademark dispute") ||
    rawContent.includes("trademark conflict") ||
    rawContent.includes("trademark complaint") ||
    rawContent.includes("trademark objection") ||
    rawContent.includes("legal dispute") ||
    rawContent.includes("legal proceedings") ||
    rawContent.includes("legal action") ||
    rawContent.includes("court order") ||
    rawContent.includes("court ordered") ||
    rawContent.includes("court proceeding") ||
    rawContent.includes("arbitration") ||
    rawContent.includes("pending arbitration") ||
    rawContent.includes("in arbitration") ||
    rawContent.includes("dispute resolution") ||
    rawContent.includes("locked for dispute") ||
    rawContent.includes("lock for dispute") ||
    rawContent.includes("locked pending") ||
    /\bstatus\s*:\s*(?:dispute|disputed|in-dispute)\b/.test(rawContent) ||
    // German (.de / .at)
    rawContent.includes("streitfall") ||
    rawContent.includes("rechtstreit") ||
    rawContent.includes("widerspruch") ||
    rawContent.includes("markenstreit") ||
    rawContent.includes("schiedsverfahren") ||
    // French (.fr)
    rawContent.includes("litige") ||
    rawContent.includes("en litige") ||
    rawContent.includes("différend") ||
    rawContent.includes("contentieux") ||
    rawContent.includes("arbitrage") ||
    // Spanish
    rawContent.includes("disputa") ||
    rawContent.includes("en disputa") ||
    rawContent.includes("conflicto de dominio") ||
    rawContent.includes("procedimiento arbitral") ||
    // Italian
    rawContent.includes("contesa") ||
    rawContent.includes("in contesa") ||
    rawContent.includes("disputa di dominio") ||
    rawContent.includes("procedimento arbitrale") ||
    // Portuguese
    rawContent.includes("disputa de domínio") ||
    rawContent.includes("arbitragem") ||
    // Dutch
    rawContent.includes("geschil") ||
    rawContent.includes("in geschil") ||
    rawContent.includes("arbitrage") ||
    // Polish
    rawContent.includes("spór domenowy") ||
    rawContent.includes("postępowanie arbitrażowe") ||
    // Russian
    rawContent.includes("спор") ||
    rawContent.includes("арбитраж") ||
    rawContent.includes("судебное") ||
    // Ukrainian
    rawContent.includes("спір") ||
    rawContent.includes("арбітраж") ||
    // Japanese
    rawContent.includes("係争中") ||
    rawContent.includes("異議申立") ||
    rawContent.includes("紛争") ||
    rawContent.includes("仲裁") ||
    // Korean
    rawContent.includes("분쟁 중") ||
    rawContent.includes("분쟁") ||
    rawContent.includes("중재") ||
    // Chinese (Simplified)
    rawContent.includes("争议中") ||
    rawContent.includes("域名争议") ||
    rawContent.includes("商标争议") ||
    rawContent.includes("仲裁中") ||
    rawContent.includes("法律纠纷") ||
    // Arabic
    rawContent.includes("نزاع") ||
    rawContent.includes("تحكيم") ||
    rawContent.includes("في نزاع") ||
    // Hebrew
    rawContent.includes("סכסוך") ||
    rawContent.includes("בוררות") ||
    // Turkish
    rawContent.includes("uyuşmazlık") ||
    rawContent.includes("ihtilaf") ||
    rawContent.includes("tahkim");

  // ── GUARD: A domain with registrar + creation + expiration date is definitively
  // registered. Reserved/prohibited domains have no registrar or dates.
  // Without this guard, WHOIS boilerplate text (e.g. RegistrarSafe privacy
  // notice containing "withheld") triggers false reserved/prohibited positives.
  const isDefinitelyRegistered =
    result.registrar && result.registrar !== "Unknown" &&
    result.creationDate && result.creationDate !== "Unknown" &&
    result.expirationDate && result.expirationDate !== "Unknown";

  const isProhibited =
    !isDefinitelyRegistered &&
    (prohibitCheckText.includes("prohibited") ||
    prohibitCheckText.includes("registrationprohibited") ||
    prohibitCheckText.includes("cannot be registered") ||
    prohibitCheckText.includes("not available for registration") ||
    prohibitCheckText.includes("not-available") ||
    prohibitCheckText.includes("ineligible") ||
    prohibitCheckText.includes("forbidden") ||
    prohibitCheckText.includes("registry-prohibited") ||
    prohibitCheckText.includes("registrybanned") ||
    rawHasProhibited);

  function makeStatus(
    type: RegistrationStatusType,
    color: string,
    dotColor: string,
    isPremiumReserved = false,
  ) {
    return { type, label: isZh ? STATUS_LABELS[type].zh : STATUS_LABELS[type].en, color, dotColor, isPremiumReserved };
  }

  if (isProhibited)
    return makeStatus("prohibited", "text-red-600 border-red-400/50 bg-red-50 dark:bg-red-950/20", "bg-red-500");

  // "reserved" should not be triggered by "registry-hold" (that is a hold, not a reserve)
  // Also guarded: an actively registered domain (has registrar + dates) cannot be reserved.
  const isReserved =
    !isDefinitelyRegistered &&
    (prohibitCheckText.includes("reserved") ||
    allStatusText.includes("reserved-delegated") ||
    allStatusText.includes("registryreserved") ||
    allStatusText.includes("registry-reserved") ||
    allStatusText.includes("registry-premium") ||
    rawHasReserved);

  // A "premium reserved" domain is held by the registry for sale — different
  // from an "official use" reserved domain.  Both display as "reserved" but
  // carry different descriptions in the info card.
  const isPremiumReserved =
    allStatusText.includes("registry-premium") ||
    rawHasPremiumReserved;

  if (isReserved)
    return makeStatus("reserved", "text-amber-600 border-amber-400/50 bg-amber-50 dark:bg-amber-950/20", "bg-amber-500", isPremiumReserved);

  const isRedemption =
    allStatusText.includes("redemptionperiod") ||
    allStatusText.includes("redemption period") ||
    allStatusText.includes("redemption-period");

  if (isRedemption)
    return makeStatus("redemption", "text-purple-600 border-purple-400/50 bg-purple-50 dark:bg-purple-950/20", "bg-purple-500");

  const isPendingDelete =
    allStatusText.includes("pendingdelete") ||
    allStatusText.includes("pending delete") ||
    allStatusText.includes("pending-delete");

  if (isPendingDelete)
    return makeStatus("pending-delete", "text-slate-600 border-slate-400/50 bg-slate-50 dark:bg-slate-950/20", "bg-slate-500");

  // ── DISPUTE — check before hold (more specific; UDRP domains often have serverHold too)
  const isDispute =
    allStatusText.includes("dispute") ||
    allStatusText.includes("udrp") ||
    allStatusText.includes("locked-udrp") ||
    allStatusText.includes("adr") ||
    rawHasDispute;

  if (isDispute)
    return makeStatus("dispute", "text-rose-600 border-rose-400/50 bg-rose-50 dark:bg-rose-950/20", "bg-rose-500");

  // ── HOLD / SUSPENDED — Match EPP codes ("serverhold") and hyphenated / spaced variants
  const hasServerHold =
    allStatusText.includes("serverhold") ||
    allStatusText.includes("server-hold") ||
    allStatusText.includes("server hold") ||
    allStatusText.includes("registry-hold") ||
    allStatusText.includes("registryhold");

  const hasClientHold =
    allStatusText.includes("clienthold") ||
    allStatusText.includes("client-hold") ||
    allStatusText.includes("client hold");

  const hasOk =
    allStatusText.includes(" ok ") ||
    allStatusText === "ok" ||
    allStatusText.includes("active");

  const hasSuspended =
    allStatusText.includes("suspended") ||
    allStatusText.includes("hold") ||
    allStatusText.includes("frozen") ||
    allStatusText.includes("inactive") ||
    rawHasSuspended;

  const isHold = (hasServerHold || hasClientHold || hasSuspended) && !hasOk;

  if (isHold)
    return makeStatus("hold", "text-orange-600 border-orange-400/50 bg-orange-50 dark:bg-orange-950/20", "bg-orange-500");

  return {
    type: "registered" as RegistrationStatusType,
    label: isZh ? STATUS_LABELS.registered.zh : STATUS_LABELS.registered.en,
    color: "text-emerald-600 border-emerald-400/50 bg-emerald-50 dark:bg-emerald-950/20",
    dotColor: "bg-emerald-500",
    isPremiumReserved: false,
  };
}

export const STATUS_INFO: Record<
  RegistrationStatusType,
  {
    icon: React.ReactNode;
    titleZh: string;
    titleEn: string;
    descZh: string;
    descEn: string;
    border: string;
    bg: string;
    iconBg: string;
    iconText: string;
    titleText: string;
    descText: string;
  }
> = {
  prohibited: {
    icon: <RiForbidLine className="w-5 h-5" />,
    titleZh: "禁止注册域名",
    titleEn: "Prohibited Domain",
    descZh: "该域名被注册局标记为禁止注册字符串，无法通过任何常规渠道注册。通常为政策性保护词汇或敏感字符串。",
    descEn: "This domain is marked as a prohibited string by the registry and cannot be registered through any conventional channel.",
    border: "border-red-300/60 dark:border-red-800/50",
    bg: "bg-gradient-to-r from-red-50/80 to-red-50/30 dark:from-red-950/30 dark:to-transparent",
    iconBg: "bg-red-100 dark:bg-red-900/40",
    iconText: "text-red-600 dark:text-red-400",
    titleText: "text-red-800 dark:text-red-300",
    descText: "text-red-700/80 dark:text-red-400/70",
  },
  reserved: {
    icon: <RiLockLine className="w-5 h-5" />,
    titleZh: "保留域名",
    titleEn: "Reserved Domain",
    descZh: "该域名为注册局保留域名，由官方机构专用或预留，暂不向公众开放注册。",
    descEn: "This domain is reserved by the registry for official use and is not available for public registration.",
    border: "border-amber-300/60 dark:border-amber-800/50",
    bg: "bg-gradient-to-r from-amber-50/80 to-amber-50/30 dark:from-amber-950/30 dark:to-transparent",
    iconBg: "bg-amber-100 dark:bg-amber-900/40",
    iconText: "text-amber-600 dark:text-amber-400",
    titleText: "text-amber-800 dark:text-amber-300",
    descText: "text-amber-700/80 dark:text-amber-400/70",
  },
  hold: {
    icon: <RiPauseCircleLine className="w-5 h-5" />,
    titleZh: "域名暂停",
    titleEn: "Domain On Hold",
    descZh: "该域名当前处于暂停状态（Server Hold / Client Hold），可能由于违规行为、未付款或争议被暂时锁定，无法正常解析。",
    descEn: "This domain is currently on hold (Server Hold / Client Hold) and cannot resolve normally. This is usually due to a policy violation, non-payment, or dispute.",
    border: "border-orange-300/60 dark:border-orange-800/50",
    bg: "bg-gradient-to-r from-orange-50/80 to-orange-50/30 dark:from-orange-950/30 dark:to-transparent",
    iconBg: "bg-orange-100 dark:bg-orange-900/40",
    iconText: "text-orange-600 dark:text-orange-400",
    titleText: "text-orange-800 dark:text-orange-300",
    descText: "text-orange-700/80 dark:text-orange-400/70",
  },
  dispute: {
    icon: <RiScalesLine className="w-5 h-5" />,
    titleZh: "域名争议",
    titleEn: "Domain Dispute",
    descZh: "该域名正处于 UDRP 争议程序或其他争议处理中，当前处于锁定状态，等待仲裁结果。",
    descEn: "This domain is currently undergoing a UDRP dispute or other legal proceedings and is locked pending arbitration.",
    border: "border-rose-300/60 dark:border-rose-800/50",
    bg: "bg-gradient-to-r from-rose-50/80 to-rose-50/30 dark:from-rose-950/30 dark:to-transparent",
    iconBg: "bg-rose-100 dark:bg-rose-900/40",
    iconText: "text-rose-600 dark:text-rose-400",
    titleText: "text-rose-800 dark:text-rose-300",
    descText: "text-rose-700/80 dark:text-rose-400/70",
  },
  redemption: {
    icon: <RiLoopLeftLine className="w-5 h-5" />,
    titleZh: "赎回期",
    titleEn: "Redemption Period",
    descZh: "该域名已过期并进入赎回期，原注册人可在此期间支付额外费用赎回，赎回期结束后将被公开删除。",
    descEn: "This domain has expired and entered the redemption period. The original registrant can reclaim it for an extra fee before it is deleted.",
    border: "border-purple-300/60 dark:border-purple-800/50",
    bg: "bg-gradient-to-r from-purple-50/80 to-purple-50/30 dark:from-purple-950/30 dark:to-transparent",
    iconBg: "bg-purple-100 dark:bg-purple-900/40",
    iconText: "text-purple-600 dark:text-purple-400",
    titleText: "text-purple-800 dark:text-purple-300",
    descText: "text-purple-700/80 dark:text-purple-400/70",
  },
  "pending-delete": {
    icon: <RiDeleteBin2Line className="w-5 h-5" />,
    titleZh: "待删除",
    titleEn: "Pending Delete",
    descZh: "该域名即将从注册系统中删除，删除后将重新开放注册。删除通常在 5 天内完成。",
    descEn: "This domain is about to be deleted from the registry and will soon become available for registration again.",
    border: "border-slate-300/60 dark:border-slate-700/50",
    bg: "bg-gradient-to-r from-slate-50/80 to-slate-50/30 dark:from-slate-950/30 dark:to-transparent",
    iconBg: "bg-slate-100 dark:bg-slate-800/60",
    iconText: "text-slate-600 dark:text-slate-400",
    titleText: "text-slate-700 dark:text-slate-300",
    descText: "text-slate-600/80 dark:text-slate-400/70",
  },
  available: {
    icon: <RiCheckLine className="w-5 h-5" />,
    titleZh: "域名可注册",
    titleEn: "Domain Available",
    descZh: "该域名当前未被注册，您可以立即前往域名注册商注册此域名。",
    descEn: "This domain is currently unregistered and available for purchase.",
    border: "border-emerald-300/60 dark:border-emerald-800/50",
    bg: "bg-gradient-to-r from-emerald-50/80 to-emerald-50/30 dark:from-emerald-950/30 dark:to-transparent",
    iconBg: "bg-emerald-100 dark:bg-emerald-900/40",
    iconText: "text-emerald-600 dark:text-emerald-400",
    titleText: "text-emerald-800 dark:text-emerald-300",
    descText: "text-emerald-700/80 dark:text-emerald-400/70",
  },
  registered: {
    icon: null,
    titleZh: "",
    titleEn: "",
    descZh: "",
    descEn: "",
    border: "",
    bg: "",
    iconBg: "",
    iconText: "",
    titleText: "",
    descText: "",
  },
};

export function DomainStatusInfoCard({
  type,
  locale,
  customDesc,
}: {
  type: RegistrationStatusType;
  locale: string;
  customDesc?: { zh: string; en: string };
}) {
  if (type === "registered") return null;
  const info = STATUS_INFO[type];
  const isZh = locale.startsWith("zh");
  const desc = customDesc
    ? (isZh ? customDesc.zh : customDesc.en)
    : (isZh ? info.descZh : info.descEn);
  return (
    <div
      className={cn(
        "rounded-xl border p-4 mt-5",
        "flex items-start gap-3.5",
        info.border,
        info.bg,
      )}
    >
      <div
        className={cn(
          "w-9 h-9 rounded-xl flex items-center justify-center shrink-0",
          info.iconBg,
          info.iconText,
        )}
      >
        {info.icon}
      </div>
      <div className="min-w-0">
        <p className={cn("text-sm font-semibold leading-tight", info.titleText)}>
          {isZh ? info.titleZh : info.titleEn}
        </p>
        <p className={cn("text-xs mt-1 leading-relaxed", info.descText)}>
          {desc}
        </p>
      </div>
    </div>
  );
}

