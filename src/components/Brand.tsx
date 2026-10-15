export function Brand({ onClick }: { onClick?: () => void }) {
  return (
    <div className="brand" onClick={onClick}>
      <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
        <path d="M16 2l12 5v8c0 8-5.5 13-12 15C9.5 28 4 23 4 15V7z" fill="#16a34a" />
        <path d="M11 16l3.5 3.5L21.5 12" stroke="#04130a" strokeWidth="2.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span>
        Threatready <span style={{ color: 'var(--dim)', fontWeight: 400 }}>|</span> DevSecOps Lab <small>· ShopFlow simulation</small>
      </span>
    </div>
  );
}
