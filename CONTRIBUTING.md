# Contributing to ShibaCuddles

Thank you for your interest in contributing to **ShibaCuddles**! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please read and adhere to our Code of Conduct:

- Be respectful and inclusive
- Welcome different perspectives and experiences
- Focus on constructive feedback
- Report any inappropriate behavior

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR-USERNAME/ShibaCuddles.git
cd ShibaCuddles
git remote add upstream https://github.com/thedarkonejesus/ShibaCuddles.git
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies with dev tools (hash-verified lock:
# runtime + test/lint/packaging tooling, one install)
pip install --require-hashes -r requirements-dev.lock.txt
```

### 3. Create a Feature Branch

```bash
# Fetch latest changes
git fetch upstream main

# Create new branch
git checkout -b feature/your-feature-name upstream/main
```

## Development Workflow

### Code Style

We follow **PEP 8** style guidelines. Use `black` for formatting:

```bash
# Format your code
black src/ tests/

# Check with pylint
pylint src/
```

### Writing Code

- Keep functions small and focused
- Add docstrings to all functions and classes
- Use meaningful variable names
- Add comments for complex logic

### Example Function

```python
def scan_port(host: str, port: int, timeout: int = 5) -> bool:
    """
    Check if a port is open on the given host.
    
    Args:
        host: IP address or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    try:
        socket.create_connection((host, port), timeout=timeout)
        return True
    except (socket.timeout, socket.error):
        return False
```

### Writing Tests

- Write tests for all new features
- Aim for >80% code coverage
- Use descriptive test names
- Test edge cases and error conditions

```python
import unittest
from src.device import discover_devices

class TestDeviceDiscovery(unittest.TestCase):
    def test_discover_devices_valid_subnet(self):
        """Test device discovery on valid subnet"""
        devices = discover_devices("192.168.1.0/24")
        self.assertIsInstance(devices, list)
    
    def test_discover_devices_invalid_subnet(self):
        """Test device discovery with invalid subnet"""
        with self.assertRaises(ValueError):
            discover_devices("invalid")
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html

# Run specific test
python -m pytest tests/test_device.py::TestDeviceDiscovery::test_discover_devices_valid_subnet
```

## Commit Guidelines

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

### Types

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```bash
git commit -m "feat: Add multi-threaded port scanning"
git commit -m "fix: Resolve timeout issue in device discovery"
git commit -m "docs: Update README with new examples"
git commit -m "test: Add coverage for edge cases"
```

## Submitting a Pull Request

### Before Submitting

1. **Update your branch**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests**
   ```bash
   python -m pytest tests/ -v
   ```

3. **Check code style**
   ```bash
   black src/ tests/
   pylint src/
   ```

4. **Update documentation** if needed
   - README.md for user-facing changes
   - Docstrings for API changes
   - CHANGELOG.md for notable changes

### PR Description Template

```markdown
## Description
Brief description of what this PR does

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
Describe how you tested these changes

## Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] No breaking changes
```

### What to Expect

- Code review within 2-3 days
- Feedback on implementation or style
- Requests for changes if needed
- Approval and merge once ready

## Reporting Issues

### Bug Reports

Provide:
- Clear description of the bug
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS
- Relevant logs or error messages

### Feature Requests

Include:
- Clear description of the feature
- Use case and motivation
- Possible implementation approach
- Any examples or references

## Development Tips

### Useful Commands

```bash
# Create isolated test run
python -m pytest tests/test_device.py -v

# Debug with print statements
python -m pdb main.py 192.168.1.0/24

# Check imports
python -m py_compile src/*.py

# Generate documentation
pdoc --html src/ -o docs/
```

### Project Structure Tips

- `src/` - All library code
- `tests/` - All test code (mirror `src/` structure)
- `main.py` - CLI entry point only
- Keep modules focused and single-responsibility

## Questions?

- Check [existing issues](https://github.com/thedarkonejesus/ShibaCuddles/issues)
- Look at [pull requests](https://github.com/thedarkonejesus/ShibaCuddles/pulls) for similar changes
- Open a discussion for non-urgent questions

## Recognition

Contributors will be:
- Added to the CONTRIBUTORS.md file
- Mentioned in release notes
- Given credit in commit history

Thank you for making ShibaCuddles better! 🐕
