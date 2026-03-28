import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLinksLine, RiAddLine, RiDeleteBinLine, RiEditLine,
  RiLoader4Line, RiCloseLine, RiCheckLine, RiExternalLinkLine,
  RiToggleLine, RiToggleFill, RiGlobalLine, RiFilterLine,
  RiEyeLine, RiEyeOffLine,
} from "@remixicon/react";

type FriendlyLink = {
  id: number;
  name: string;
  url: string;
  description: string | null;
  category: string | null;
  sort_order: number;
  active: boolean;
  created_at: string;
};

const EMPTY_FORM = { name: "", url: "", description: "", category: "", sort_order: "0" };

export default function AdminLinksPage() {
  const [links, setLinks] = React.useState<FriendlyLink[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [showCreate, setShowCreate] = React.useState(false);
  const [editId, setEditId] = React.useState<number | null>(null);
  const [form, setForm] = React.useState(EMPTY_FORM);
  const [saving, setSaving] = React.useState(false);
  const [deletingId, setDeletingId] = React.useState<number | null>(null);
  const [categoryFilter, setCategoryFilter] = React.useState<string>("__all__");
  const [showHidden, setShowHidden] = React.useState(true);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/links");
      const data = await res.json();
      setLinks(data.links || []);
    } catch {
      toast.error("加载失败");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);

  function openCreate() {
    setEditId(null);
    setForm(EMPTY_FORM);
    setShowCreate(true);
  }

  function openEdit(link: FriendlyLink) {
    setShowCreate(false);
    setEditId(link.id);
    setForm({
      name: link.name,
      url: link.url,
      description: link.description || "",
      category: link.category || "",
      sort_order: String(link.sort_order),
    });
  }

  function cancelForm() {
    setShowCreate(false);
    setEditId(null);
    setForm(EMPTY_FORM);
  }

  async function handleSave() {
    if (!form.name.trim()) { toast.error("请填写链接名称"); return; }
    let rawUrl = form.url.trim();
    if (!rawUrl) { toast.error("请填写链接地址"); return; }
    if (!/^https?:\/\//i.test(rawUrl)) rawUrl = `https://${rawUrl}`;
    try { new URL(rawUrl); } catch { toast.error("URL 格式不正确"); return; }
    setSaving(true);
    try {
      const body = {
        ...(editId ? { id: editId } : {}),
        name: form.name.trim(),
        url: rawUrl,
        description: form.description.trim() || null,
        category: form.category.trim() || null,
        sort_order: Number(form.sort_order) || 0,
        active: true,
      };
      const res = await fetch("/api/admin/links", {
        method: editId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) { const d = await res.json(); toast.error(d.error || "保存失败"); return; }
      toast.success(editId ? "链接已更新" : "链接已添加");
      cancelForm();
      await load();
    } catch {
      toast.error("网络错误");
    } finally {
      setSaving(false);
    }
  }

  async function toggleActive(link: FriendlyLink) {
    try {
      await fetch("/api/admin/links", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: link.id, active: !link.active }),
      });
      setLinks(ls => ls.map(l => l.id === link.id ? { ...l, active: !l.active } : l));
    } catch {
      toast.error("操作失败");
    }
  }

  async function handleDelete(id: number) {
    setDeletingId(id);
    try {
      const res = await fetch("/api/admin/links", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) { toast.error("删除失败"); return; }
      toast.success("已删除");
      setLinks(ls => ls.filter(l => l.id !== id));
      if (editId === id) cancelForm();
    } catch {
      toast.error("网络错误");
    } finally {
      setDeletingId(null);
    }
  }

  const categories = Array.from(new Set(links.map(l => l.category).filter(Boolean))) as string[];
  const activeCount = links.filter(l => l.active).length;
  const hiddenCount = links.filter(l => !l.active).length;

  const filtered = links.filter(l => {
    const catOk = categoryFilter === "__all__" || l.category === categoryFilter || (categoryFilter === "__none__" && !l.category);
    const visOk = showHidden || l.active;
    return catOk && visOk;
  });

  return (
    <AdminLayout title="友情链接管理">
      <Head><title>友情链接 · Admin</title></Head>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">友情链接</h2>
            <p className="text-xs text-muted-foreground mt-0.5">管理网站推荐的友情链接，显示在 /links 页面</p>
          </div>
          <Button onClick={openCreate} className="rounded-xl h-9 gap-2 font-semibold">
            <RiAddLine className="w-4 h-4" />添加链接
          </Button>
        </div>

        {/* Stats */}
        {links.length > 0 && (
          <div className="grid grid-cols-3 gap-2.5">
            <div className="glass-panel border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold tabular-nums">{links.length}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">全部链接</p>
            </div>
            <div className="glass-panel border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold tabular-nums text-emerald-500">{activeCount}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">已显示</p>
            </div>
            <div className="glass-panel border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold tabular-nums text-muted-foreground">{categories.length}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">分类数</p>
            </div>
          </div>
        )}

        {/* Category filter + visibility toggle */}
        {links.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
            <button
              onClick={() => setCategoryFilter("__all__")}
              className={cn(
                "text-xs px-3 py-1.5 rounded-full font-medium transition-all",
                categoryFilter === "__all__"
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              全部<span className={cn("ml-1.5 text-[10px]", categoryFilter === "__all__" ? "opacity-70" : "opacity-60")}>{links.length}</span>
            </button>
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={cn(
                  "text-xs px-3 py-1.5 rounded-full font-medium transition-all",
                  categoryFilter === cat
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                {cat}
                <span className={cn("ml-1.5 text-[10px]", categoryFilter === cat ? "opacity-70" : "opacity-60")}>
                  {links.filter(l => l.category === cat).length}
                </span>
              </button>
            ))}
            {links.some(l => !l.category) && (
              <button
                onClick={() => setCategoryFilter("__none__")}
                className={cn(
                  "text-xs px-3 py-1.5 rounded-full font-medium transition-all",
                  categoryFilter === "__none__"
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                未分类
                <span className={cn("ml-1.5 text-[10px]", categoryFilter === "__none__" ? "opacity-70" : "opacity-60")}>
                  {links.filter(l => !l.category).length}
                </span>
              </button>
            )}
            {hiddenCount > 0 && (
              <button
                onClick={() => setShowHidden(v => !v)}
                className={cn(
                  "ml-auto text-xs px-3 py-1.5 rounded-full font-medium transition-all flex items-center gap-1.5",
                  showHidden
                    ? "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
                    : "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400"
                )}
              >
                {showHidden ? <RiEyeOffLine className="w-3 h-3" /> : <RiEyeLine className="w-3 h-3" />}
                {showHidden ? `隐藏已隐藏 (${hiddenCount})` : `显示已隐藏 (${hiddenCount})`}
              </button>
            )}
          </div>
        )}

        {/* Create / Edit form */}
        {(showCreate || editId !== null) && (
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <div className="px-5 py-3 flex items-center justify-between border-b border-border bg-muted/30">
              <div className="flex items-center gap-2">
                <RiLinksLine className="w-4 h-4 text-emerald-500" />
                <h3 className="text-sm font-bold">{editId ? "编辑链接" : "添加新链接"}</h3>
              </div>
              <button onClick={cancelForm} className="p-1 rounded-lg hover:bg-muted/60 text-muted-foreground transition-colors">
                <RiCloseLine className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label className="text-xs font-semibold">链接名称 *</Label>
                  <Input
                    value={form.name}
                    onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="如：GitHub、朋友的博客"
                    className="h-9 rounded-xl"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs font-semibold">链接地址 *</Label>
                  <Input
                    value={form.url}
                    onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                    placeholder="https://example.com"
                    className="h-9 rounded-xl font-mono text-sm"
                    type="url"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs font-semibold">简介 <span className="text-muted-foreground font-normal">（可选）</span></Label>
                  <Input
                    value={form.description}
                    onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                    placeholder="一句话介绍这个网站"
                    className="h-9 rounded-xl"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs font-semibold">分类 <span className="text-muted-foreground font-normal">（可选）</span></Label>
                    <Input
                      value={form.category}
                      onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                      placeholder="如：推荐、友链"
                      className="h-9 rounded-xl"
                      list="category-list"
                    />
                    <datalist id="category-list">
                      {categories.map(c => <option key={c} value={c} />)}
                    </datalist>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs font-semibold">排序 <span className="text-muted-foreground font-normal">（越小越靠前）</span></Label>
                    <Input
                      value={form.sort_order}
                      onChange={e => setForm(f => ({ ...f, sort_order: e.target.value }))}
                      type="number"
                      min="0"
                      className="h-9 rounded-xl"
                    />
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <Button onClick={handleSave} disabled={saving} className="h-9 rounded-xl gap-2 font-semibold">
                  {saving
                    ? <><RiLoader4Line className="w-4 h-4 animate-spin" />保存中…</>
                    : <><RiCheckLine className="w-4 h-4" />{editId ? "保存修改" : "添加链接"}</>}
                </Button>
                <Button variant="outline" onClick={cancelForm} disabled={saving} className="h-9 rounded-xl">取消</Button>
              </div>
            </div>
          </div>
        )}

        {/* Links list */}
        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="px-5 py-3 flex items-center justify-between border-b border-border bg-muted/30">
            <div className="flex items-center gap-2">
              <RiLinksLine className="w-4 h-4 text-muted-foreground" />
              <h3 className="text-sm font-bold">
                {categoryFilter === "__all__" ? "全部链接" : categoryFilter === "__none__" ? "未分类链接" : `分类：${categoryFilter}`}
              </h3>
            </div>
            <span className="text-xs text-muted-foreground">{filtered.length} 条</span>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
              <RiLoader4Line className="w-5 h-5 animate-spin" />
              <span className="text-sm">加载中…</span>
            </div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <RiLinksLine className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">
                {links.length === 0 ? "还没有添加任何链接" : "该筛选条件下暂无链接"}
              </p>
              {links.length === 0 && (
                <p className="text-xs text-muted-foreground/60 mt-1">点击"添加链接"来创建第一条友情链接</p>
              )}
            </div>
          ) : (
            <div className="divide-y divide-border">
              {filtered.map(link => (
                <div
                  key={link.id}
                  className={cn(
                    "flex items-center gap-3 px-5 py-3.5 transition-colors",
                    !link.active && "opacity-50",
                    editId === link.id && "bg-primary/5"
                  )}
                >
                  <div className="w-8 h-8 rounded-lg bg-muted/60 flex items-center justify-center shrink-0">
                    <RiGlobalLine className="w-4 h-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold">{link.name}</span>
                      {link.category && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-primary/10 text-primary font-medium">
                          {link.category}
                        </span>
                      )}
                      {!link.active && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground">已隐藏</span>
                      )}
                    </div>
                    <a
                      href={link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[11px] text-primary hover:underline flex items-center gap-0.5 mt-0.5 w-fit"
                    >
                      {link.url.replace(/^https?:\/\//, "").split("/")[0]}
                      <RiExternalLinkLine className="w-2.5 h-2.5" />
                    </a>
                    {link.description && (
                      <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{link.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <span className="text-[10px] text-muted-foreground/50 hidden sm:block mr-1">#{link.sort_order}</span>
                    <button
                      onClick={() => toggleActive(link)}
                      className={cn(
                        "p-1.5 rounded-lg transition-colors",
                        link.active ? "text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-950/30" : "text-muted-foreground hover:bg-muted"
                      )}
                      title={link.active ? "点击隐藏" : "点击显示"}
                    >
                      {link.active ? <RiToggleFill className="w-4 h-4" /> : <RiToggleLine className="w-4 h-4" />}
                    </button>
                    <button
                      onClick={() => openEdit(link)}
                      className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                      title="编辑"
                    >
                      <RiEditLine className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(link.id)}
                      disabled={deletingId === link.id}
                      className="p-1.5 rounded-lg text-muted-foreground hover:bg-red-50 dark:hover:bg-red-950/20 hover:text-red-500 transition-colors"
                      title="删除"
                    >
                      {deletingId === link.id
                        ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                        : <RiDeleteBinLine className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="p-3 rounded-xl bg-muted/40 border border-border/60">
          <p className="text-xs font-medium mb-1">友情链接说明</p>
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            友情链接显示在 <code className="font-mono">/links</code> 页面，仅显示已启用的链接。可通过分类字段将链接分组（同名分类会自动归组）。排序数值越小越靠前，相同排序按添加时间降序。
          </p>
        </div>
      </div>
    </AdminLayout>
  );
}
