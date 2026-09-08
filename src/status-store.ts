export class StatusStore {
  private revoked = new Set<number>();

  revoke(no: number) {
    this.revoked.add(no);
  }

  restore(no: number) {
    this.revoked.delete(no);
  }

  isRevoked(no: number) {
    return this.revoked.has(no);
  }

  check(credential: any) {
    const item = credential?.credentialStatus;
    if(!item) return {verified: true};

    const no = Number(item.myStatusIndex);
    if(!Number.isInteger(no) || no < 0) {
      return {verified: false, reason: 'Invalid status index'};
    }
    if(this.isRevoked(no)) {
      return {verified: false, reason: 'Credential has been revoked'};
    }
    return {verified: true};
  }
}
