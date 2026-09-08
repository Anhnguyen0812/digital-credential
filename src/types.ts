export type DegreeSubject = {
  id: string;
  studentName: string;
  studentCode: string;
  degreeName: string;
  major: string;
  graduationDate: string;
  gpa: number;
  classification: string;
  graduated: boolean;
};

export type DegreeInput = {
  id: string;
  subject: DegreeSubject;
  statusIndex?: number;
};

export type VerifyResult = {
  verified: boolean;
  reason?: string;
  cryptoVerified?: boolean;
  statusVerified?: boolean;
};

export type PresentationRequest = {
  nonce: string;
  audience: string;
};

export type SimplePresentation = {
  type: string[];
  holder: string;
  nonce: string;
  audience: string;
  createdAt: string;
  verifiableCredential: any[];
};
