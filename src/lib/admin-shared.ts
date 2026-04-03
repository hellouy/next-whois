export const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "9208522@qq.com";

export function isAdmin(email?: string | null): boolean {
  return !!email && email.toLowerCase().trim() === ADMIN_EMAIL.toLowerCase().trim();
}
