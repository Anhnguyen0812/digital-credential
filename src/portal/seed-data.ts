// Du lieu mau cho demo. Mat khau chung cua moi tai khoan demo: DEMO_PASSWORD (bam scrypt khi seed, khong luu ban ro).
export const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'Demo@2026';

export type IssuerRole = 'ADMIN' | 'REGISTRAR' | 'APPROVER';

export interface SeedIssuerUser {
  username: string;
  fullName: string;
  email: string;
  role: IssuerRole;
  title: string;
}

export const ISSUER_USERS: SeedIssuerUser[] = [
  {username: 'admin', fullName: 'Lê Minh Quân', email: 'admin@vnu.edu.vn', role: 'ADMIN', title: 'Quản trị hệ thống'},
  {username: 'chuyenvien', fullName: 'Nguyễn Thị Hồng', email: 'hongnt@vnu.edu.vn', role: 'REGISTRAR', title: 'Chuyên viên Phòng Đào tạo'},
  {username: 'truongphong', fullName: 'PGS.TS Trần Văn Bình', email: 'binhtv@vnu.edu.vn', role: 'APPROVER', title: 'Trưởng phòng Đào tạo'}
];

export interface StudentProfile {
  studentCode: string;
  fullName: string;
  email: string;
  emailActive: boolean;       // false: cuu sinh vien da bi thu hoi email truong -> phai dung VNeID
  nationalId: string;         // so CCCD (dinh danh VNeID)
  dateOfBirth: string;
  className: string;
  major: string;
  degreeName: string;
  cohort: string;
  status: 'STUDYING' | 'GRADUATED';
  graduationDate?: string;
  gpa?: string;
  classification?: string;
}

export const STUDENTS: StudentProfile[] = [
  {studentCode: '23020009', fullName: 'Nguyễn Phi Anh', email: '23020009@vnu.edu.vn', emailActive: true, nationalId: '001203004567', dateOfBirth: '2005-03-14', className: 'K68-CNTT1', major: 'Công nghệ thông tin', degreeName: 'Cử nhân Công nghệ thông tin', cohort: 'K68', status: 'GRADUATED', graduationDate: '2026-06-30', gpa: '3.65', classification: 'Xuất sắc'},
  {studentCode: '23020114', fullName: 'Trần Minh Khôi', email: '23020114@vnu.edu.vn', emailActive: true, nationalId: '001205007788', dateOfBirth: '2005-07-02', className: 'K68-CNTT2', major: 'Khoa học máy tính', degreeName: 'Cử nhân Khoa học máy tính', cohort: 'K68', status: 'GRADUATED', graduationDate: '2026-06-30', gpa: '3.28', classification: 'Giỏi'},
  {studentCode: '23020231', fullName: 'Lê Thảo Vy', email: '23020231@vnu.edu.vn', emailActive: true, nationalId: '001305001234', dateOfBirth: '2005-11-20', className: 'K68-HTTT', major: 'Hệ thống thông tin', degreeName: 'Cử nhân Hệ thống thông tin', cohort: 'K68', status: 'GRADUATED', graduationDate: '2026-06-30', gpa: '3.05', classification: 'Khá'},
  {studentCode: '24020377', fullName: 'Phạm Quốc Bảo', email: '24020377@vnu.edu.vn', emailActive: true, nationalId: '001206009900', dateOfBirth: '2006-01-09', className: 'K69-CNTT3', major: 'Công nghệ thông tin', degreeName: 'Cử nhân Công nghệ thông tin', cohort: 'K69', status: 'STUDYING'},
  {studentCode: '24020412', fullName: 'Đỗ Hà My', email: '24020412@vnu.edu.vn', emailActive: true, nationalId: '001306004411', dateOfBirth: '2006-05-27', className: 'K69-ATTT', major: 'An toàn thông tin', degreeName: 'Kỹ sư An toàn thông tin', cohort: 'K69', status: 'STUDYING'},
  {studentCode: '22020198', fullName: 'Vũ Đức Long', email: '22020198@vnu.edu.vn', emailActive: true, nationalId: '001204002233', dateOfBirth: '2004-09-15', className: 'K67-KTMT', major: 'Kỹ thuật máy tính', degreeName: 'Kỹ sư Kỹ thuật máy tính', cohort: 'K67', status: 'GRADUATED', graduationDate: '2026-01-15', gpa: '2.94', classification: 'Khá'},
  {studentCode: '11020345', fullName: 'Phạm Thu Trang', email: '11020345@vnu.edu.vn', emailActive: false, nationalId: '001193005566', dateOfBirth: '1993-04-18', className: 'K56-CNTT', major: 'Công nghệ thông tin', degreeName: 'Cử nhân Công nghệ thông tin', cohort: 'K56', status: 'GRADUATED', graduationDate: '2015-06-25', gpa: '3.41', classification: 'Giỏi'},
  {studentCode: '12020876', fullName: 'Hoàng Gia Huy', email: '12020876@vnu.edu.vn', emailActive: false, nationalId: '001194008877', dateOfBirth: '1994-12-03', className: 'K57-ĐTVT', major: 'Điện tử viễn thông', degreeName: 'Kỹ sư Điện tử viễn thông', cohort: 'K57', status: 'GRADUATED', graduationDate: '2016-07-10', gpa: '2.88', classification: 'Khá'}
];

export type RpRole = 'HR_MANAGER' | 'HR_STAFF';

export interface SeedRpUser {
  username: string;
  fullName: string;
  email: string;
  orgId: string;
  role: RpRole;
}

export const RP_ORGS: Record<string, {name: string; shortName: string; domain: string}> = {
  fpt: {name: 'FPT Software', shortName: 'FPT', domain: 'fpt.com'},
  viettel: {name: 'Viettel Cyber Security', shortName: 'VCS', domain: 'viettel.com.vn'},
  vng: {name: 'VNG Corporation', shortName: 'VNG', domain: 'vng.com.vn'}
};

export const RP_USERS: SeedRpUser[] = [
  {username: 'hr.fpt', fullName: 'Ngô Thanh Hương', email: 'huongnt@fpt.com', orgId: 'fpt', role: 'HR_MANAGER'},
  {username: 'staff.fpt', fullName: 'Bùi Văn Nam', email: 'nambv@fpt.com', orgId: 'fpt', role: 'HR_STAFF'},
  {username: 'hr.viettel', fullName: 'Đặng Thu Hà', email: 'hadt@viettel.com.vn', orgId: 'viettel', role: 'HR_MANAGER'},
  {username: 'hr.vng', fullName: 'Lý Hoàng Sơn', email: 'sonlh@vng.com.vn', orgId: 'vng', role: 'HR_MANAGER'}
];

// Mau chung chi hoc phan de chuyen vien chon khi lap de nghi cap
export const COURSE_CATALOG = [
  {courseCode: 'INT3306', courseName: 'An toàn và Bảo mật Hệ thống Thông tin', courseHours: 45, skills: ['W3C Verifiable Credentials', 'Applied Cryptography', 'Zero Trust']},
  {courseCode: 'INT3117', courseName: 'Kiểm thử và Đảm bảo chất lượng phần mềm', courseHours: 45, skills: ['Software Testing', 'CI/CD', 'Quality Assurance']},
  {courseCode: 'INT3405', courseName: 'Học máy', courseHours: 60, skills: ['Machine Learning', 'Python', 'Data Analysis']},
  {courseCode: 'INT2208', courseName: 'Công nghệ phần mềm', courseHours: 45, skills: ['Agile', 'UML', 'Requirements Engineering']}
];
