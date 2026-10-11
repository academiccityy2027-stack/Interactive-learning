# Learning Universe: separate Teacher / Student login

## Safe deployment order
1. Back up the Cloudflare D1 database `learning-universe`.
2. Upload updated files to the `teacher-student-login` GitHub branch, **not main**.
3. Apply `0001_teacher_employee_login.sql` once using the Cloudflare D1 Console. Do not rerun the ALTER statement if the column already exists.
4. Test branch deployment and then merge to main when ready. Since `wrangler.jsonc` points at `index.js`, that file is the deployed application.

## Approved teacher accounts
The teacher must already have an account. Verify employment before marking it as a teacher.
The new admin-only API `POST /api/admin/employee` associates a verified employee number to an existing account; body: `{ "id": "EXISTING_USER_ID", "employeeNumber": "3334" }`. It requires admin session authentication and the existing request headers. Then an administrator can grant `teacher` with the existing admin role assignment. The current admin UI does not yet have an employee-number input; manually assigning an employee number through the D1 console is another option.

Example after confirming username and employee number against the school's staff roster:

```sql
UPDATE users SET employee_number='3334', role='teacher' WHERE username='verified_username' AND role='student';
```

Numbers must be unique. Avoid entering teacher rosters, passwords, or private employment details into the public repository. **Employee number is an identifier, not a password.** Teacher sign in requires number + username + password.

## Test checklist
- Student portal accepts a valid student account.
- Teacher portal rejects the same student credentials.
- Teacher portal accepts approved teacher with correct employee number, username and password.
- Wrong employee number or wrong password is rejected.
- Existing admin can sign in via Student login and still sees the admin dashboard.
- Registration and password recovery still work.

No accounts are automatically imported from the roster in this package.
