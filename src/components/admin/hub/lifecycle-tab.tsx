import React from "react";
import { TldRulesWorkspace } from "@/pages/admin/tld-rules";

export function LifecycleTab() {
  return <TldRulesWorkspace embedded initialTab="lifecycle" workspaceTabs={["lifecycle"]} />;
}

export default LifecycleTab;