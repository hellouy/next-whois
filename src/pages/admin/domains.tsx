import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { RiArrowRightLine, RiGlobalLine } from "@remixicon/react";

export default function DomainsPage() {
  const router = useRouter();
  const tabParam = router.query.tab as string | undefined;

  React.useEffect(() => {
    const target = tabParam === "failures"
      ? "/admin/tld-rules?inner=failures"
      : "/admin/tld-rules?inner=lifecycle";
    router.replace(target);
  }, [tabParam]);

  return (
    <AdminLayout title="域名管理">
      <Head><title>域名管理 · Admin</title></Head>
      <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
        <RiGlobalLine className="w-10 h-10 text-muted-foreground/40" />
        <p className="text-sm text-muted-foreground">正在跳转到 TLD 规则页…</p>
        <Button variant="outline" size="sm" onClick={() => router.replace("/admin/tld-rules")}>
          <RiArrowRightLine className="w-4 h-4 mr-1.5" />立即跳转
        </Button>
      </div>
    </AdminLayout>
  );
}
