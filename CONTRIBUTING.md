# Contributing to laravel-iam-auth

Thank you for your interest in contributing! This package is maintained by [Hack The Box](https://www.hackthebox.com) and primary development happens internally, but we welcome community contributions.

## Bug Reports

Please open a [GitHub issue](https://github.com/hackthebox/laravel-iam-auth/issues) with:

- PHP and Laravel versions
- Package version
- Steps to reproduce
- Expected vs. actual behavior
- Relevant configuration (redact credentials)

## Feature Requests

Open a [GitHub issue](https://github.com/hackthebox/laravel-iam-auth/issues) describing the use case before writing code. This avoids wasted effort on changes that may not align with the package's direction.

## Pull Requests

1. Fork the repository and create a branch from `main`
2. Keep PRs focused: one feature or fix per PR
3. Add or update tests for your changes
4. Ensure all checks pass before submitting
5. Write a clear PR description explaining the "why"

### Development Setup

```bash
git clone git@github.com:<your-fork>/laravel-iam-auth.git
cd laravel-iam-auth
composer install
```

### Running Tests

```bash
vendor/bin/phpunit
```

### Static Analysis

```bash
vendor/bin/phpstan analyse
```

### Coding Standards

- Follow [PSR-12](https://www.php-fig.org/psr/psr-12/)
- All PRs must pass PHPStan at the configured level
- Keep changes consistent with the existing code style

## Commit Messages

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add support for Aurora Serverless
fix: handle expired token edge case
docs: clarify EKS Pod Identity setup
```

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Please see [SECURITY.md](SECURITY.md) for reporting instructions.

## Code of Conduct

Be respectful and constructive. We are all here to build something useful.
