# Contributing to Enhanced Botnet Implementation

Thank you for your interest in contributing to the Enhanced Botnet Implementation! This document provides guidelines for contributing to this educational and research project.

## 🚨 Important Legal and Ethical Notice

**This project is strictly for educational and research purposes only.** Any contributions must:

- Be made with educational intent only
- Comply with all applicable laws and regulations
- Not be intended for malicious use
- Include appropriate disclaimers and documentation
- Focus on defensive cybersecurity research

By contributing, you agree to these terms and acknowledge that misuse of this software is strictly prohibited.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Documentation Guidelines](#documentation-guidelines)

## 📜 Code of Conduct

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

### Unacceptable Behavior

- Use of sexualized language or imagery
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Sharing malicious code or exploits
- Any conduct that could reasonably be considered inappropriate in a professional setting

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of cybersecurity concepts
- Familiarity with async/await programming

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/Enhanced-Botnet-Implementation.git
   cd Enhanced-Botnet-Implementation
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/GizzZmo/Enhanced-Botnet-Implementation.git
   ```

## 🔧 Development Setup

### Environment Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-asyncio black flake8 bandit mypy
   ```

3. Verify installation:
   ```bash
   python -c "import utils; print('✅ Setup successful')"
   ```

### Configuration

Create a `.env` file for local development (never commit this file):
```bash
BOTNET_HOST=127.0.0.1
BOTNET_PORT=9999
BOTNET_LOG_LEVEL=DEBUG
BOTNET_ADMIN_PASSWORD=your_test_password
```

## 🎨 Code Style Guidelines

### Python Code Style

We follow PEP 8 with some modifications:

- **Line length**: Maximum 127 characters
- **Imports**: Use absolute imports, group by standard library, third-party, local
- **Naming**: 
  - Functions and variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Private members: prefix with `_`

### Type Hints

All new code must include type hints:

```python
from typing import Optional, Dict, List, Any

def process_command(command: str, bot_id: Optional[str] = None) -> Dict[str, Any]:
    """Process a command with proper type hints."""
    pass
```

### Docstrings

Use Google-style docstrings for all functions, classes, and modules:

```python
def encrypt_data(data: bytes, key: Optional[bytes] = None) -> bytes:
    """
    Encrypt data using AES-256-CBC encryption.
    
    Args:
        data: Raw data to encrypt
        key: Optional encryption key (generates new if None)
    
    Returns:
        Encrypted data with IV prepended
        
    Raises:
        ValueError: If data is invalid
        
    Example:
        >>> encrypted = encrypt_data(b"secret message")
        >>> assert len(encrypted) > len(b"secret message")
    """
    pass
```

### Code Formatting

Use Black for code formatting:
```bash
black .
```

Use flake8 for linting:
```bash
flake8 . --max-line-length=127
```

## 🧪 Testing Requirements

### Test Coverage

- All new code must include tests
- Aim for >90% test coverage
- Include both unit and integration tests
- Test edge cases and error conditions

### Test Categories

1. **Unit Tests**: Test individual functions/classes
   ```python
   def test_encryption_functionality():
       encryption = SecureEncryption()
       data = b"test data"
       encrypted = encryption.encrypt(data)
       decrypted = encryption.decrypt(encrypted)
       assert decrypted == data
   ```

2. **Security Tests**: Validate security features
   ```python
   def test_input_sanitization():
       validator = InputValidator()
       malicious_input = "command\x00\x01\x02"
       sanitized = validator.sanitize_command(malicious_input)
       assert '\x00' not in sanitized
   ```

3. **Performance Tests**: Ensure performance requirements
   ```python
   def test_encryption_performance():
       encryption = SecureEncryption()
       start_time = time.time()
       for _ in range(1000):
           encryption.encrypt(b"test")
       assert time.time() - start_time < 1.0
   ```

4. **Async Tests**: Test async functionality
   ```python
   async def test_async_bot_tracking():
       tracker = BotTracker()
       await tracker.add_bot("test_bot", "127.0.0.1")
       assert tracker.get_bot_count() == 1
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test categories
pytest tests/test_security.py
pytest tests/test_performance.py

# Run async tests
pytest tests/test_botnet_controller.py::TestBotnetControllerAsync
```

## 🔒 Security Guidelines

### Security Requirements

1. **No Hardcoded Secrets**: Use environment variables or config files
2. **Input Validation**: Validate all user inputs
3. **Secure Encryption**: Use AES-256 minimum, no XOR encryption
4. **Logging Safety**: Never log sensitive data
5. **Error Handling**: Don't expose sensitive information in errors

### Security Checklist

Before submitting code, verify:

- [ ] No hardcoded passwords, keys, or secrets
- [ ] All inputs are validated and sanitized
- [ ] Encryption uses secure algorithms (AES-256+)
- [ ] No sensitive data in logs
- [ ] Error messages don't reveal system information
- [ ] Dependencies are pinned and audited
- [ ] Code passes security scans (bandit, safety)

### Security Review Process

All security-related changes require:

1. Security-focused code review
2. Automated security scanning
3. Manual security testing
4. Documentation updates

## 📝 Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `security`: Security improvement
- `perf`: Performance improvement
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `docs`: Documentation changes
- `style`: Code style changes
- `ci`: CI/CD changes

### Examples

```
feat(encryption): add AES-256-GCM support

- Implement AES-256-GCM encryption mode
- Add authenticated encryption with associated data
- Include performance benchmarks
- Update security documentation

Closes #123
```

```
security(validation): improve input sanitization

- Add null byte removal from commands
- Implement length limiting for user inputs
- Add regex-based validation for IP addresses
- Include comprehensive test coverage

BREAKING CHANGE: Command length now limited to 1024 characters
```

## 🔄 Pull Request Process

### Before Submitting

1. **Update Documentation**: Ensure README and docstrings are current
2. **Run Tests**: All tests must pass locally
3. **Security Scan**: Run bandit and safety checks
4. **Code Quality**: Run flake8 and black
5. **Performance Check**: Verify no performance regressions

### PR Requirements

1. **Clear Description**: Explain what changes and why
2. **Issue Reference**: Link to related issues
3. **Testing Evidence**: Show test results
4. **Security Impact**: Describe security implications
5. **Breaking Changes**: Clearly document any breaking changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security improvement
- [ ] Performance enhancement
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass
- [ ] Performance tests pass

## Security Impact
Describe any security implications

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No hardcoded secrets
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Peer Review**: At least one maintainer review required
3. **Security Review**: Security-focused review for security changes
4. **Testing**: Manual testing in isolated environment
5. **Documentation Review**: Ensure documentation is accurate

## 🐛 Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Bug Description**
Clear description of the bug

**To Reproduce**
Steps to reproduce the behavior

**Expected Behavior**
What you expected to happen

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Python Version: [e.g., 3.11.0]
- Dependencies: [relevant package versions]

**Security Impact**
Any potential security implications

**Additional Context**
Any other relevant information
```

### Feature Requests

Use the feature request template:

```markdown
**Feature Description**
Clear description of the desired feature

**Use Case**
Explain the educational/research use case

**Implementation Ideas**
Suggestions for implementation

**Security Considerations**
Any security implications to consider

**Additional Context**
Any other relevant information
```

## 📚 Documentation Guidelines

### Documentation Requirements

1. **README Updates**: Keep README.md current with features
2. **API Documentation**: Document all public APIs
3. **Security Documentation**: Document security features and best practices
4. **Examples**: Provide clear usage examples
5. **Architecture**: Document system architecture and design decisions

### Documentation Style

- Use clear, concise language
- Include code examples
- Provide security warnings where appropriate
- Keep examples up-to-date
- Use proper markdown formatting

### Building Documentation

```bash
# Generate API documentation
python -c "help(utils)" > docs/utils_api.md

# Check documentation coverage
docstring-coverage . --verbose
```

## 🛡️ Security Responsible Disclosure

If you discover a security vulnerability:

1. **Do NOT** create a public issue
2. **Do NOT** commit fixes to public branches
3. **DO** email the maintainers privately
4. **DO** provide detailed information about the vulnerability
5. **DO** allow time for responsible disclosure

## 📞 Getting Help

- **Questions**: Create a discussion or issue
- **Documentation**: Check README.md and inline documentation
- **Security**: Contact maintainers privately for security issues
- **Development**: Join development discussions in issues

## 🏆 Recognition

Contributors will be recognized in:

- README.md contributors section
- Release notes for significant contributions
- GitHub contributors page

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to the Enhanced Botnet Implementation! Your contributions help make cybersecurity education and research more effective and accessible.

**Remember: This project is for educational and research purposes only. Use responsibly and ethically.**