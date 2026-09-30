import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "درهم | محرك حماية البيانات والامتثال",
  description: "منصة محلية لفحص المستندات واكتشاف البيانات الشخصية وإخفائها وفق متطلبات حماية البيانات.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ar" dir="rtl" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
