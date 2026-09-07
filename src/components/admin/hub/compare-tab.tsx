import React from "react";
import { TldRulesWorkspace } from "@/pages/admin/tld-rules";

export function CompareTab() {
  return <TldRulesWorkspace embedded initialTab="compare" workspaceTabs={["compare"]} />;
}

export default CompareTab;