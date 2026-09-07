import type { NextPage } from "next";
import { AdminLayout } from "@/components/admin-layout";
import { ProvidersSection } from "@/components/admin/providers-section";

const AdminApiPage: NextPage = () => {
  return (
    <AdminLayout title="API 接入">
      <ProvidersSection />
    </AdminLayout>
  );
};

export default AdminApiPage;