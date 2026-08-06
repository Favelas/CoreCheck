markdown
# Contributing to CoreCheck

Thank you for contributing to CoreCheck. To maintain our strict technical bar, zero-type-error policy, and production stability, all contributions must adhere to the following workflow.

---

## 1. Development Principles

1. **Zero TypeScript Errors (`npm run typecheck`):** Pull requests with a single type warning or error will be automatically rejected.
2. **Zero False-Positive Target:** Rules must include verifiable evidence bounded by a strict 2 KB payload limit.
3. **Scope Discipline:** Features outside CoreCheck v1.0 specifications will be rejected or deferred to post-revenue iterations.

---

## 2. Local Setup & Verification

```bash
# Clone repository
git clone [https://github.com/your-org/corecheck.git](https://github.com/your-org/corecheck.git)
cd corecheck

# Install dependencies
npm install

# Run TypeScript compilation check
npm run typecheck

# Run test suite
npm run test