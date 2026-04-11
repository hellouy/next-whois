export type EppStatusCategory =
  | "ok"
  | "client"
  | "server"
  | "pending"
  | "grace"
  | "redemption"
  | "unknown";

export type EppStatusInfo = {
  description: string;
  descriptionZh: string;
  category: EppStatusCategory;
  displayName: string;
};

const categoryColors: Record<EppStatusCategory, string> = {
  ok: "#10b981",
  client: "#3b82f6",
  server: "#8b5cf6",
  pending: "#f59e0b",
  grace: "#0ea5e9",
  redemption: "#ef4444",
  unknown: "#71717a",
};

const categoryLabels: Record<EppStatusCategory, string> = {
  ok: "Active",
  client: "Client Lock",
  server: "Server Lock",
  pending: "Pending",
  grace: "Grace Period",
  redemption: "Redemption",
  unknown: "Unknown",
};

const EPP_STATUS_MAP: Record<string, EppStatusInfo> = {
  ok: {
    displayName: "ok",
    description:
      "This is the standard status for a domain, meaning no pending operations or prohibitions.",
    descriptionZh: "域名处于标准状态，无待处理操作或禁止项。",
    category: "ok",
  },
  active: {
    displayName: "active",
    description: "The domain is active and delegated in the DNS.",
    descriptionZh: "域名已激活并在 DNS 中正常委派解析。",
    category: "ok",
  },
  inactive: {
    displayName: "inactive",
    description:
      "The domain has not been delegated in the DNS and will not resolve.",
    descriptionZh: "域名未在 DNS 中委派，无法解析。",
    category: "redemption",
  },
  addperiod: {
    displayName: "addPeriod",
    description:
      "Initial registration grace period. The domain can be deleted for a refund within a few days of registration.",
    descriptionZh: "初始注册宽限期。注册后数日内可删除域名并获得退款。",
    category: "grace",
  },
  autorenewperiod: {
    displayName: "autoRenewPeriod",
    description:
      "Auto-renewal grace period after automatic renewal. Registrar may delete registration for a refund.",
    descriptionZh: "自动续费后的宽限期。注册商可删除注册以获得退款。",
    category: "grace",
  },
  renewperiod: {
    displayName: "renewPeriod",
    description:
      "Renewal grace period. The registrar may delete the registration for a refund.",
    descriptionZh: "续费宽限期。注册商可在此期间删除注册以获得退款。",
    category: "grace",
  },
  transferperiod: {
    displayName: "transferPeriod",
    description:
      "Transfer grace period after a successful transfer. The new registrar may delete for a refund.",
    descriptionZh: "转移成功后的宽限期。新注册商可在此期间删除域名以获得退款。",
    category: "grace",
  },
  clientdeleteprohibited: {
    displayName: "clientDeleteProhibited",
    description:
      "The registrar has set this status to prevent the domain from being deleted.",
    descriptionZh: "注册商已设置此状态，禁止删除该域名。",
    category: "client",
  },
  clienthold: {
    displayName: "clientHold",
    description:
      "The registrar has suspended the domain. It will not resolve in the DNS.",
    descriptionZh: "注册商已暂停该域名，域名将无法在 DNS 中解析。",
    category: "client",
  },
  clientrenewprohibited: {
    displayName: "clientRenewProhibited",
    description: "The registrar has locked the domain to prevent renewal.",
    descriptionZh: "注册商已锁定该域名，禁止续费。",
    category: "client",
  },
  clienttransferprohibited: {
    displayName: "clientTransferProhibited",
    description:
      "The registrar has locked the domain to prevent transfer to another registrar.",
    descriptionZh: "注册商已锁定该域名，禁止转移至其他注册商。",
    category: "client",
  },
  clientupdateprohibited: {
    displayName: "clientUpdateProhibited",
    description:
      "The registrar has locked the domain to prevent any changes to the domain record.",
    descriptionZh: "注册商已锁定该域名，禁止修改域名记录。",
    category: "client",
  },
  serverdeleteprohibited: {
    displayName: "serverDeleteProhibited",
    description:
      "The registry has set this status to prevent the domain from being deleted.",
    descriptionZh: "注册局已设置此状态，禁止删除该域名。",
    category: "server",
  },
  serverhold: {
    displayName: "serverHold",
    description:
      "The registry has suspended the domain. It will not resolve in the DNS.",
    descriptionZh: "注册局已暂停该域名，域名将无法在 DNS 中解析。",
    category: "server",
  },
  serverrenewprohibited: {
    displayName: "serverRenewProhibited",
    description: "The registry has locked the domain to prevent renewal.",
    descriptionZh: "注册局已锁定该域名，禁止续费。",
    category: "server",
  },
  servertransferprohibited: {
    displayName: "serverTransferProhibited",
    description: "The registry has locked the domain to prevent transfer.",
    descriptionZh: "注册局已锁定该域名，禁止转移。",
    category: "server",
  },
  serverupdateprohibited: {
    displayName: "serverUpdateProhibited",
    description: "The registry has locked the domain to prevent any changes.",
    descriptionZh: "注册局已锁定该域名，禁止任何修改。",
    category: "server",
  },
  pendingcreate: {
    displayName: "pendingCreate",
    description:
      "A request to create the domain has been received and is being processed.",
    descriptionZh: "域名创建请求已收到，正在处理中。",
    category: "pending",
  },
  pendingdelete: {
    displayName: "pendingDelete",
    description:
      "The domain is scheduled for deletion. It cannot be restored and will be purged soon.",
    descriptionZh: "域名已被计划删除，无法恢复，即将被清除。",
    category: "pending",
  },
  pendingrenew: {
    displayName: "pendingRenew",
    description:
      "A request to renew the domain has been received and is being processed.",
    descriptionZh: "域名续费请求已收到，正在处理中。",
    category: "pending",
  },
  pendingrestore: {
    displayName: "pendingRestore",
    description:
      "A restore request has been received after redemption period. Pending registry approval.",
    descriptionZh: "赎回期后已收到恢复请求，等待注册局审批。",
    category: "pending",
  },
  pendingtransfer: {
    displayName: "pendingTransfer",
    description:
      "A transfer request has been received and is pending approval or rejection.",
    descriptionZh: "转移请求已收到，等待批准或拒绝。",
    category: "pending",
  },
  pendingupdate: {
    displayName: "pendingUpdate",
    description:
      "A request to update the domain has been received and is being processed.",
    descriptionZh: "域名更新请求已收到，正在处理中。",
    category: "pending",
  },
  redemptionperiod: {
    displayName: "redemptionPeriod",
    description:
      "The domain has been deleted but can still be restored by the registrar for an additional fee.",
    descriptionZh: "域名已被删除，但注册商仍可付费恢复。",
    category: "redemption",
  },

  registered: {
    displayName: "registered",
    description: "The domain is registered and active.",
    descriptionZh: "域名已注册并处于正常运营状态。",
    category: "ok",
  },
  delegated: {
    displayName: "delegated",
    description:
      "The domain has been delegated in the DNS and is fully operational.",
    descriptionZh: "域名已在 DNS 中完成委派，可正常访问。",
    category: "ok",
  },
  connect: {
    displayName: "connect",
    description: "The domain is connected and active in the DNS.",
    descriptionZh: "域名已连接并在 DNS 中正常解析。",
    category: "ok",
  },
  connected: {
    displayName: "connected",
    description: "The domain is connected and active in the DNS.",
    descriptionZh: "域名已连接并在 DNS 中正常解析。",
    category: "ok",
  },
  live: {
    displayName: "live",
    description: "The domain is live and resolving in the DNS.",
    descriptionZh: "域名处于上线状态，可正常在 DNS 中解析访问。",
    category: "ok",
  },
  allocated: {
    displayName: "allocated",
    description: "The domain has been allocated to a registrant.",
    descriptionZh: "域名已分配给注册人。",
    category: "ok",
  },
  assigned: {
    displayName: "assigned",
    description: "The domain has been assigned and is in use.",
    descriptionZh: "域名已分配并投入使用。",
    category: "ok",
  },
  activated: {
    displayName: "activated",
    description: "The domain has been activated and is operational.",
    descriptionZh: "域名已激活，处于正常运营状态。",
    category: "ok",
  },
  activé: {
    displayName: "Activé",
    description: "The domain is active (French ccTLD status).",
    descriptionZh: "域名处于激活状态（法语 ccTLD 注册局状态：已启用）。",
    category: "ok",
  },
  enregistré: {
    displayName: "Enregistré",
    description: "The domain is registered (French ccTLD status).",
    descriptionZh: "域名已注册（法语 ccTLD 注册局状态：已登记）。",
    category: "ok",
  },
  registriert: {
    displayName: "registriert",
    description: "The domain is registered (German ccTLD status).",
    descriptionZh: "域名已注册（德语 ccTLD 注册局状态：已注册）。",
    category: "ok",
  },
  aktiv: {
    displayName: "aktiv",
    description: "The domain is active (German ccTLD status).",
    descriptionZh: "域名已激活（德语 ccTLD 注册局状态：活跃中）。",
    category: "ok",
  },
  registrado: {
    displayName: "registrado",
    description: "The domain is registered (Spanish/Portuguese ccTLD status).",
    descriptionZh: "域名已注册（西班牙语/葡萄牙语 ccTLD 注册局状态：已注册）。",
    category: "ok",
  },
  activo: {
    displayName: "activo",
    description: "The domain is active (Spanish ccTLD status).",
    descriptionZh: "域名已激活（西班牙语 ccTLD 注册局状态：活跃中）。",
    category: "ok",
  },
  ativo: {
    displayName: "ativo",
    description: "The domain is active (Portuguese ccTLD status).",
    descriptionZh: "域名已激活（葡萄牙语 ccTLD 注册局状态：活跃中）。",
    category: "ok",
  },
  actief: {
    displayName: "actief",
    description: "The domain is active (Dutch ccTLD status).",
    descriptionZh: "域名已激活（荷兰语 ccTLD 注册局状态：活跃中）。",
    category: "ok",
  },
  geregistreerd: {
    displayName: "geregistreerd",
    description: "The domain is registered (Dutch ccTLD status).",
    descriptionZh: "域名已注册（荷兰语 ccTLD 注册局状态：已注册）。",
    category: "ok",
  },
  registrato: {
    displayName: "registrato",
    description: "The domain is registered (Italian ccTLD status).",
    descriptionZh: "域名已注册（意大利语 ccTLD 注册局状态：已注册）。",
    category: "ok",
  },
  rezervovan: {
    displayName: "rezervovan",
    description:
      "The domain is reserved by the registry (Czech/Slovak ccTLD status).",
    descriptionZh: "域名被注册局保留（捷克/斯洛伐克语 ccTLD 状态：已预留）。",
    category: "server",
  },
  kaydedildi: {
    displayName: "kaydedildi",
    description: "The domain is registered (Turkish ccTLD status).",
    descriptionZh: "域名已注册（土耳其语 ccTLD 注册局状态：已注册）。",
    category: "ok",
  },
  reserved: {
    displayName: "reserved",
    description: "The domain is reserved by the registry and cannot be registered by the public.",
    descriptionZh: "域名被注册局预留，公众无法注册。",
    category: "server",
  },
  registryreserved: {
    displayName: "registry-reserved",
    description: "The domain is reserved by the registry (detected from WHOIS free text).",
    descriptionZh: "注册局已将此域名标记为保留域名（从 WHOIS 原始文本中检测）。",
    category: "server",
  },
  registrationprohibited: {
    displayName: "registrationProhibited",
    description: "The domain cannot be registered — marked as prohibited by the registry.",
    descriptionZh: "该域名被注册局标记为禁止注册，无法通过任何渠道注册。",
    category: "server",
  },
  blocked: {
    displayName: "blocked",
    description: "The domain is blocked by the registry and cannot be registered.",
    descriptionZh: "域名已被注册局封锁，无法注册。",
    category: "server",
  },
  suspended: {
    displayName: "suspended",
    description:
      "The domain has been suspended by the registry or registrar and will not resolve.",
    descriptionZh: "域名已被注册局或注册商暂停，无法解析。",
    category: "server",
  },
  locked: {
    displayName: "locked",
    description:
      "The domain is locked against transfers or changes. Contact your registrar to unlock.",
    descriptionZh: "域名已被锁定，无法转移或修改，请联系注册商解锁。",
    category: "client",
  },
  hold: {
    displayName: "hold",
    description:
      "The domain is on hold and will not resolve in the DNS until released.",
    descriptionZh: "域名处于冻结状态，解除前无法在 DNS 中解析。",
    category: "pending",
  },
  onhold: {
    displayName: "on-hold",
    description: "The domain is on hold and will not resolve until released.",
    descriptionZh: "域名处于冻结暂停状态，解除前无法解析。",
    category: "pending",
  },
  expired: {
    displayName: "expired",
    description:
      "The domain registration has expired. It may enter a grace or redemption period before deletion.",
    descriptionZh: "域名注册已到期，可能进入宽限期或赎回期，之后将被删除。",
    category: "redemption",
  },
  quarantine: {
    displayName: "quarantine",
    description:
      "The domain is in a quarantine period after expiry before being released for re-registration.",
    descriptionZh: "域名到期后处于隔离期，期满后将重新开放注册。",
    category: "redemption",
  },
  pendingrelease: {
    displayName: "pendingRelease",
    description: "The domain is pending release back to the available pool.",
    descriptionZh: "域名等待释放回可注册池。",
    category: "pending",
  },
  pendingpurge: {
    displayName: "pendingPurge",
    description: "The domain is pending purge and will be permanently deleted.",
    descriptionZh: "域名即将被永久清除删除。",
    category: "pending",
  },
  pendingrenewal: {
    displayName: "pendingRenewal",
    description:
      "A renewal request has been received and is pending processing.",
    descriptionZh: "续费请求已收到，等待处理中。",
    category: "pending",
  },
  graceperiod: {
    displayName: "gracePeriod",
    description:
      "The domain is in a grace period, typically following expiry or registration.",
    descriptionZh: "域名处于宽限期（通常发生在到期或注册之后）。",
    category: "grace",
  },
  clientexpired: {
    displayName: "clientExpired",
    description: "The domain registration has expired at the registrar level.",
    descriptionZh: "域名注册已在注册商层面到期。",
    category: "redemption",
  },
  serverexpired: {
    displayName: "serverExpired",
    description: "The domain registration has expired at the registry level.",
    descriptionZh: "域名注册已在注册局层面到期。",
    category: "redemption",
  },
  deletionpending: {
    displayName: "deletionPending",
    description:
      "The domain is pending deletion and will be removed from the registry soon.",
    descriptionZh: "域名等待删除，即将从注册局中移除。",
    category: "pending",
  },
  tobedeleted: {
    displayName: "toBeDeleted",
    description: "The domain is scheduled to be deleted.",
    descriptionZh: "域名已计划删除。",
    category: "pending",
  },
  supprimé: {
    displayName: "Supprimé",
    description: "The domain has been deleted (French ccTLD status).",
    descriptionZh: "域名已被删除（法语 ccTLD 注册局状态：已删除）。",
    category: "pending",
  },
  expiré: {
    displayName: "Expiré",
    description: "The domain registration has expired (French ccTLD status).",
    descriptionZh: "域名已到期（法语 ccTLD 注册局状态：已过期）。",
    category: "redemption",
  },
  gelöscht: {
    displayName: "gelöscht",
    description: "The domain has been deleted (German ccTLD status).",
    descriptionZh: "域名已被删除（德语 ccTLD 注册局状态：已删除）。",
    category: "pending",
  },
  gesperrt: {
    displayName: "gesperrt",
    description: "The domain is blocked/locked (German ccTLD status).",
    descriptionZh: "域名已被封锁或锁定（德语 ccTLD 注册局状态：已封锁）。",
    category: "server",
  },
  transferprohibited: {
    displayName: "transferProhibited",
    description: "Transfer of this domain is prohibited.",
    descriptionZh: "该域名禁止转移。",
    category: "client",
  },
  updateprohibited: {
    displayName: "updateProhibited",
    description: "Updates to this domain record are prohibited.",
    descriptionZh: "该域名的记录禁止修改。",
    category: "client",
  },
  deleteprohibited: {
    displayName: "deleteProhibited",
    description: "Deletion of this domain is prohibited.",
    descriptionZh: "该域名禁止删除。",
    category: "client",
  },
  renewprohibited: {
    displayName: "renewProhibited",
    description: "Renewal of this domain is prohibited.",
    descriptionZh: "该域名禁止续费。",
    category: "client",
  },
  noregistrar: {
    displayName: "noRegistrar",
    description: "The domain has no registrar assigned.",
    descriptionZh: "该域名未分配注册商。",
    category: "unknown",
  },
  unregistered: {
    displayName: "unregistered",
    description: "The domain is not currently registered.",
    descriptionZh: "该域名当前未注册。",
    category: "unknown",
  },
  notregistered: {
    displayName: "notRegistered",
    description: "The domain is not registered.",
    descriptionZh: "该域名未注册。",
    category: "unknown",
  },
  free: {
    displayName: "free",
    description: "The domain is free and available for registration.",
    descriptionZh: "域名空闲，可供注册。",
    category: "unknown",
  },
  available: {
    displayName: "available",
    description: "The domain is available for registration.",
    descriptionZh: "域名可供注册。",
    category: "unknown",
  },
  withheld: {
    displayName: "withheld",
    description:
      "The domain has been withheld by the registry and is not available for registration.",
    descriptionZh: "域名已被注册局扣留，不可注册。",
    category: "server",
  },
  dispute: {
    displayName: "dispute",
    description:
      "The domain is under dispute and cannot be transferred or modified until the dispute is resolved.",
    descriptionZh: "域名存在争议，争议解决前不得转移或修改。",
    category: "server",
  },
  underdispute: {
    displayName: "underDispute",
    description: "The domain is currently under dispute.",
    descriptionZh: "域名当前处于争议处理中。",
    category: "server",
  },
  courtorder: {
    displayName: "courtOrder",
    description: "The domain is subject to a court order.",
    descriptionZh: "域名受法院命令约束。",
    category: "server",
  },
  abuse: {
    displayName: "abuse",
    description: "The domain has been flagged for abuse and may be suspended.",
    descriptionZh: "域名已被标记为滥用，可能遭到暂停。",
    category: "server",
  },
  awaitingverification: {
    displayName: "awaitingVerification",
    description: "The domain registration is awaiting verification.",
    descriptionZh: "域名注册待验证。",
    category: "pending",
  },
  pendingverification: {
    displayName: "pendingVerification",
    description: "Domain registrant verification is pending.",
    descriptionZh: "域名注册人验证待处理中。",
    category: "pending",
  },
  verificationfailed: {
    displayName: "verificationFailed",
    description: "Domain registrant verification failed. The domain may be suspended.",
    descriptionZh: "域名注册人验证失败，域名可能被暂停。",
    category: "redemption",
  },
  clientsuspended: {
    displayName: "clientSuspended",
    description: "The registrar has suspended this domain.",
    descriptionZh: "注册商已暂停该域名。",
    category: "client",
  },
  serversuspended: {
    displayName: "serverSuspended",
    description: "The registry has suspended this domain.",
    descriptionZh: "注册局已暂停该域名。",
    category: "server",
  },
  registrantchangeprohibited: {
    displayName: "registrantChangeProhibited",
    description: "The registrant of this domain cannot be changed.",
    descriptionZh: "该域名的注册人不可更改。",
    category: "client",
  },
  associatewith: {
    displayName: "associateWith",
    description:
      "The domain is associated with another domain or registry entity.",
    descriptionZh: "域名与另一域名或注册局实体相关联。",
    category: "ok",
  },
  ok_serverrenewprohibited: {
    displayName: "ok/serverRenewProhibited",
    description: "The domain is active but renewal is prohibited by the registry.",
    descriptionZh: "域名正常，但注册局已禁止续费。",
    category: "server",
  },

  prohibited: {
    displayName: "Prohibited",
    description:
      "This domain is marked as a prohibited string by the registry. It cannot be registered through any conventional channel, typically because it is a policy-protected keyword or reserved term.",
    descriptionZh:
      "该域名被注册局标记为禁止注册字符串，无法通过任何常规渠道注册。通常为政策性保护词汇或敏感字符串。",
    category: "server",
  },
  prohibitedstring: {
    displayName: "Prohibited String",
    description:
      "This domain contains a prohibited string as defined by registry policy and cannot be registered by the general public.",
    descriptionZh: "该域名包含注册局政策规定的禁止字符串，公众无法注册。",
    category: "server",
  },
  cannotberegistered: {
    displayName: "Cannot Be Registered",
    description:
      "This domain cannot be registered through normal channels as defined by the registry policy.",
    descriptionZh: "该域名无法通过常规途径注册，由注册局政策规定禁止。",
    category: "server",
  },
  notavailable: {
    displayName: "Not Available",
    description: "This domain is not available for registration at this time.",
    descriptionZh: "该域名当前不可注册。",
    category: "server",
  },
  unavailable: {
    displayName: "Unavailable",
    description: "This domain is unavailable for registration.",
    descriptionZh: "该域名不可注册。",
    category: "server",
  },
  inuse: {
    displayName: "In Use",
    description: "This domain is currently in use and registered.",
    descriptionZh: "该域名当前正在使用中，已被注册。",
    category: "ok",
  },
  taken: {
    displayName: "Taken",
    description: "This domain has already been registered by someone.",
    descriptionZh: "该域名已被他人注册。",
    category: "ok",
  },
  nodelegation: {
    displayName: "No Delegation",
    description:
      "The domain has no name server delegation set. It is registered but will not resolve in the DNS.",
    descriptionZh: "该域名未设置名称服务器委派，已注册但无法在 DNS 中解析。",
    category: "redemption",
  },
  pendingallocation: {
    displayName: "Pending Allocation",
    description: "The domain is pending allocation by the registry.",
    descriptionZh: "域名正在等待注册局分配。",
    category: "pending",
  },
  pendingregistration: {
    displayName: "Pending Registration",
    description: "The domain registration is pending completion.",
    descriptionZh: "域名注册正在处理中。",
    category: "pending",
  },
  pendingexpiry: {
    displayName: "Pending Expiry",
    description: "The domain is approaching expiry and is pending renewal.",
    descriptionZh: "域名即将到期，等待续费处理。",
    category: "pending",
  },
  pendingtransaction: {
    displayName: "Pending Transaction",
    description: "A transaction on this domain is currently pending.",
    descriptionZh: "该域名当前有待处理的交易操作。",
    category: "pending",
  },
  autorenew: {
    displayName: "Auto-Renew",
    description: "The domain is set to auto-renew upon expiry.",
    descriptionZh: "该域名设置为到期自动续费。",
    category: "ok",
  },
  autorenewed: {
    displayName: "Auto-Renewed",
    description: "The domain has been automatically renewed.",
    descriptionZh: "该域名已自动完成续费。",
    category: "ok",
  },
  registrantverified: {
    displayName: "Registrant Verified",
    description: "The registrant's identity has been verified by the registry.",
    descriptionZh: "注册人身份已通过注册局验证。",
    category: "ok",
  },
  whoisprotected: {
    displayName: "WHOIS Protected",
    description: "The domain's WHOIS contact information is protected/hidden.",
    descriptionZh: "该域名的 WHOIS 联系信息受保护/已隐藏。",
    category: "ok",
  },
  privacyprotected: {
    displayName: "Privacy Protected",
    description: "The domain's registrant contact information is protected by a privacy service.",
    descriptionZh: "该域名的注册人联系信息受隐私保护服务保护。",
    category: "ok",
  },
  redemption: {
    displayName: "Redemption",
    description:
      "The domain has expired and entered the redemption period. It can be restored by the original registrant for an additional fee.",
    descriptionZh:
      "域名已到期并进入赎回期，原注册人可以支付额外费用恢复该域名。",
    category: "redemption",
  },
  argp: {
    displayName: "Auto-Renew Grace Period",
    description:
      "Auto-renewal grace period. The registrar may delete the domain for a refund.",
    descriptionZh: "自动续费宽限期。注册商可在此期间删除域名以获得退款。",
    category: "grace",
  },
  rgp: {
    displayName: "Redemption Grace Period",
    description:
      "Redemption grace period. The domain may be restored by the registrant for a fee.",
    descriptionZh: "赎回宽限期。注册人可支付费用恢复域名。",
    category: "grace",
  },
  agp: {
    displayName: "Add Grace Period",
    description:
      "Initial registration grace period. The domain can be deleted for a refund.",
    descriptionZh: "初始注册宽限期。域名可被删除并退款。",
    category: "grace",
  },
  transferlock: {
    displayName: "Transfer Lock",
    description:
      "The domain is locked against transfers. Contact your registrar to unlock.",
    descriptionZh: "域名已加转移锁，请联系注册商解锁。",
    category: "client",
  },
  domaincreated: {
    displayName: "Domain Created",
    description: "The domain has been newly created in the registry.",
    descriptionZh: "域名已在注册局新建。",
    category: "ok",
  },
  domainrenewed: {
    displayName: "Domain Renewed",
    description: "The domain registration has been successfully renewed.",
    descriptionZh: "域名注册已成功续费。",
    category: "ok",
  },
  domaintransferred: {
    displayName: "Domain Transferred",
    description: "The domain has been transferred to a new registrar.",
    descriptionZh: "域名已转移至新注册商。",
    category: "ok",
  },
  domainsuspended: {
    displayName: "Domain Suspended",
    description: "The domain has been suspended and will not resolve.",
    descriptionZh: "域名已被暂停，无法解析。",
    category: "server",
  },
  domaindeleted: {
    displayName: "Domain Deleted",
    description: "The domain has been deleted from the registry.",
    descriptionZh: "域名已从注册局删除。",
    category: "pending",
  },
  outzone: {
    displayName: "Out of Zone",
    description:
      "The domain is out of the DNS zone and will not resolve. Name servers may be missing or invalid.",
    descriptionZh: "域名不在 DNS 区域内，无法解析，名称服务器可能缺失或无效。",
    category: "redemption",
  },
  offhold: {
    displayName: "Off Hold",
    description: "The domain has been released from hold status and is active.",
    descriptionZh: "域名已从冻结状态释放，恢复正常。",
    category: "ok",
  },
  throttled: {
    displayName: "Throttled",
    description: "The domain has been throttled by the registry due to excessive queries.",
    descriptionZh: "域名因查询过于频繁被注册局限流。",
    category: "server",
  },
  errored: {
    displayName: "Errored",
    description: "The domain is in an error state at the registry level.",
    descriptionZh: "域名在注册局层面处于错误状态。",
    category: "redemption",
  },
  registrylocked: {
    displayName: "Registry Locked",
    description:
      "The registry has placed a lock on this domain preventing any changes, transfers, or deletion.",
    descriptionZh: "注册局已锁定该域名，禁止任何修改、转移或删除操作。",
    category: "server",
  },
  registrarheld: {
    displayName: "Registrar Held",
    description: "The domain is being held by the registrar.",
    descriptionZh: "域名被注册商暂时扣押。",
    category: "client",
  },
  registryheld: {
    displayName: "Registry Held",
    description: "The domain is being held by the registry.",
    descriptionZh: "域名被注册局暂时扣押。",
    category: "server",
  },
  nolongeractive: {
    displayName: "No Longer Active",
    description: "This domain is no longer active and has ceased to function.",
    descriptionZh: "该域名已不再处于激活状态，已停止运行。",
    category: "redemption",
  },
  deactivated: {
    displayName: "Deactivated",
    description: "The domain has been deactivated and will not resolve.",
    descriptionZh: "域名已被停用，无法解析。",
    category: "redemption",
  },
  disabled: {
    displayName: "Disabled",
    description: "The domain is disabled and not currently active.",
    descriptionZh: "域名已禁用，当前不处于激活状态。",
    category: "redemption",
  },
  rejected: {
    displayName: "Rejected",
    description: "The domain registration or request has been rejected by the registry.",
    descriptionZh: "域名注册或申请已被注册局拒绝。",
    category: "server",
  },
  challenged: {
    displayName: "Challenged",
    description: "The domain registration is being challenged by a third party.",
    descriptionZh: "域名注册正受到第三方质疑。",
    category: "server",
  },
  underreview: {
    displayName: "Under Review",
    description:
      "The domain is currently under review by the registry or registrar.",
    descriptionZh: "域名正在被注册局或注册商审查中。",
    category: "pending",
  },
  reviewing: {
    displayName: "Reviewing",
    description: "The domain registration is currently being reviewed.",
    descriptionZh: "域名注册正在审查中。",
    category: "pending",
  },
  termination: {
    displayName: "Termination",
    description: "The domain is in the process of being terminated.",
    descriptionZh: "域名正在被终止处理中。",
    category: "pending",
  },
  terminated: {
    displayName: "Terminated",
    description: "The domain registration has been terminated.",
    descriptionZh: "域名注册已被终止。",
    category: "pending",
  },
  cancelled: {
    displayName: "Cancelled",
    description: "The domain registration has been cancelled.",
    descriptionZh: "域名注册已取消。",
    category: "pending",
  },
  canceled: {
    displayName: "Canceled",
    description: "The domain registration has been canceled.",
    descriptionZh: "域名注册已取消。",
    category: "pending",
  },
  pendingcontactverification: {
    displayName: "Pending Contact Verification",
    description: "The domain registrant's contact details are pending verification.",
    descriptionZh: "域名注册人的联系信息正在等待验证。",
    category: "pending",
  },
};

function normalizeStatusKey(status: string): string {
  return status
    .toLowerCase()
    .replace(/[\s_\-/]/g, "")
    .replace(/[àáâãäå]/g, "a")
    .replace(/[èéêë]/g, "e")
    .replace(/[ìíîï]/g, "i")
    .replace(/[òóôõö]/g, "o")
    .replace(/[ùúûü]/g, "u")
    .replace(/[ýÿ]/g, "y")
    .replace(/[ñ]/g, "n")
    .replace(/[ç]/g, "c")
    .replace(/[ß]/g, "ss")
    .replace(/[æ]/g, "ae")
    .replace(/[ø]/g, "o")
    .replace(/[ð]/g, "d")
    .replace(/[þ]/g, "th");
}

export function getEppStatusInfo(status: string): EppStatusInfo | null {
  if (typeof status !== "string" || !status) return null;
  const withAccents = status.toLowerCase().replace(/[\s_\-/]/g, "");
  if (EPP_STATUS_MAP[withAccents]) return EPP_STATUS_MAP[withAccents];
  const normalized = normalizeStatusKey(status);
  return EPP_STATUS_MAP[normalized] || null;
}

export function getEppStatusColor(status: string): string {
  const info = getEppStatusInfo(status);
  if (!info) return "#71717a";
  return categoryColors[info.category];
}

export function getEppStatusDisplayName(status: string): string {
  const info = getEppStatusInfo(status);
  if (!info) return status;
  return info.displayName;
}

export function getEppStatusLink(status: string): string {
  const info = getEppStatusInfo(status);
  if (!info) return "https://icann.org/epp";
  return `https://icann.org/epp#${info.displayName}`;
}

export function getEppStatusLabel(status: string): string {
  const info = getEppStatusInfo(status);
  if (!info) return "Unknown";
  return categoryLabels[info.category];
}

export function getEppStatusDescription(
  status: string,
  locale: string,
): string | null {
  const info = getEppStatusInfo(status);
  if (!info) return null;
  if (locale === "zh" || locale === "zh-tw") return info.descriptionZh;
  return info.description;
}

export { categoryColors, categoryLabels };
