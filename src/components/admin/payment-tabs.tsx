import { RiBankCardLine, RiPriceTag3Line, RiBillLine } from "@remixicon/react";
import { PageTabs } from "@/components/page-tabs";

export const PAYMENT_TABS = [
  { href: "/admin/payment/settings", label: "支付配置", icon: RiBankCardLine },
  { href: "/admin/payment/plans",    label: "套餐管理",  icon: RiPriceTag3Line },
  { href: "/admin/payment/orders",   label: "订单管理",  icon: RiBillLine },
];

export function PaymentTabs() {
  return <PageTabs tabs={PAYMENT_TABS} />;
}