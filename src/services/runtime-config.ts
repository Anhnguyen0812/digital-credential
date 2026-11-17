export function serviceOptions(service: 'issuer' | 'wallet' | 'verifier') {
  const demoMode = process.env.DEMO_MODE === '1';
  if(process.env.NODE_ENV === 'production') {
    if(demoMode) throw new Error('DEMO_MODE chỉ dành cho môi trường cục bộ');
    const required = service === 'issuer'
      ? ['POSTGRES_URL', 'MASTER_KMS_KEY', 'SESSION_SECRET', 'RECEIPT_SECRET']
      : service === 'wallet' ? ['WALLET_POSTGRES_URL', 'WALLET_STORAGE_KEY'] : ['POSTGRES_URL', 'RECEIPT_SECRET'];
    for(const name of required) {
      if((process.env[name]?.trim().length ?? 0) < (name.endsWith('URL') ? 1 : 32)) {
        throw new Error('Thiếu cấu hình hợp lệ cho ' + name);
      }
    }
    if(service !== 'wallet' && (process.env.DEMO_PASSWORD?.length ?? 0) < 12) {
      throw new Error('DEMO_PASSWORD cần ít nhất 12 ký tự cho tài khoản mẫu');
    }
    const secrets = required.filter(name => !name.endsWith('URL')).map(name => process.env[name]);
    if(new Set(secrets).size !== secrets.length) throw new Error('Mỗi mục đích phải dùng bí mật riêng');
  }
  return {demoMode};
}
