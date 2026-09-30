const highlights = [
  {
    number: "01",
    title: "اكتشاف البيانات الحساسة",
    description: "فحص المستندات بحثًا عن المعرفات والأرقام والبيانات الشخصية باستخدام قواعد وأنماط لغوية.",
  },
  {
    number: "02",
    title: "إخفاء قابل للمراجعة",
    description: "تجهيز نسخة منقحة وتقارير توضح أنواع البيانات المكتشفة ومستوى المخاطر.",
  },
  {
    number: "03",
    title: "تشغيل محلي",
    description: "يعالج التطبيق المكتبي الملفات على جهاز المؤسسة مع تخزين محمي عند إعداد SQLCipher.",
  },
];

export default function Home() {
  return (
    <main className="landing">
      <header className="topbar">
        <a className="brand" href="#home" aria-label="درهم، الصفحة الرئيسية">
          <span className="brand-mark" aria-hidden="true">د</span>
          <span>درهم<span className="brand-dot">.</span></span>
        </a>
        <a className="top-link" href="#capabilities">استكشف الإمكانات <span aria-hidden="true">↙</span></a>
      </header>

      <section className="hero" id="home">
        <div className="hero-copy">
          <p className="eyebrow"><span className="status-dot" /> حماية البيانات تبدأ من هنا</p>
          <h1>بياناتك الحساسة،<br /><span>تحت سيطرتك.</span></h1>
          <p className="hero-description">
            درهم محرك محلي لفحص المستندات واكتشاف البيانات الشخصية وإخفائها،
            مع أدوات تساعد فرقك على متابعة الامتثال وإدارة المخاطر.
          </p>
          <a className="primary-link" href="#capabilities">تعرّف على المنصة <span aria-hidden="true">←</span></a>
          <p className="hero-note">مصمم لمعالجة محلية ومراجعة بشرية للنتائج.</p>
        </div>

        <div className="hero-visual" aria-label="تصوير توضيحي لعملية حماية البيانات">
          <div className="orbit orbit-outer" />
          <div className="orbit orbit-inner" />
          <div className="visual-core"><span>د</span><small>حماية محلية</small></div>
          <div className="float-card card-top"><span className="card-icon">✓</span><span>فحص المستندات<small>تحليل محلي</small></span></div>
          <div className="float-card card-bottom"><span className="card-icon muted">•••</span><span>إخفاء البيانات<small>نتيجة قابلة للمراجعة</small></span></div>
          <span className="visual-caption">من الملف إلى نسخة أكثر أمانًا</span>
        </div>
      </section>

      <section className="capabilities" id="capabilities">
        <div className="section-heading">
          <p className="eyebrow">إمكانات المنصة</p>
          <h2>مسار واضح لحماية المعلومات.</h2>
        </div>
        <div className="feature-grid">
          {highlights.map((item) => (
            <article className="feature-card" key={item.number}>
              <span className="feature-number">{item.number}</span>
              <h3>{item.title}</h3>
              <p>{item.description}</p>
            </article>
          ))}
        </div>
      </section>

      <footer className="footer">
        <span>درهم © {new Date().getFullYear()}</span>
        <span>منصة حماية بيانات تعمل محليًا</span>
      </footer>
    </main>
  );
}
