# GitHub & VS Code Setup Guide

## Quick Start: Open in VS Code

### Option 1: Open directly from VS Code
1. Open VS Code
2. Click **File** → **Open Folder**
3. Navigate to: `C:\Users\zebid\ssh-trust-validator`
4. Click **Select Folder**

### Option 2: Open from Command Line
```powershell
cd C:\Users\zebid\ssh-trust-validator
code .
```

## Push to GitHub

### Step 1: Create a GitHub Repository
1. Go to [GitHub.com](https://github.com) and sign in
2. Click the **+** icon in the top right → **New repository**
3. Name it: `ssh-trust-validator` (or any name you prefer)
4. **DO NOT** initialize with README, .gitignore, or license (we already have these)
5. Click **Create repository**

### Step 2: Connect Local Repository to GitHub
After creating the repository, GitHub will show you commands. Use these:

```powershell
cd C:\Users\zebid\ssh-trust-validator

# Add the remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/ssh-trust-validator.git

# Push your code
git branch -M main
git push -u origin main
```

**Example:**
If your GitHub username is `johndoe`, the command would be:
```powershell
git remote add origin https://github.com/johndoe/ssh-trust-validator.git
```

### Step 3: Verify
1. Refresh your GitHub repository page
2. You should see all your files!

## Clone from GitHub (Later)

If you want to clone this repository on another computer:

```powershell
git clone https://github.com/YOUR_USERNAME/ssh-trust-validator.git
cd ssh-trust-validator
```

## Using VS Code with Git

### View Changes
- Open VS Code
- Click the **Source Control** icon in the left sidebar (or press `Ctrl+Shift+G`)
- You'll see all your files and can track changes

### Commit Changes
1. Make changes to your files
2. Click the **Source Control** icon
3. Stage changes (click **+** next to files)
4. Enter a commit message
5. Click **✓ Commit**
6. Click **...** → **Push** to upload to GitHub

### Pull Latest Changes
If you make changes on another computer:
1. Click **Source Control** icon
2. Click **...** → **Pull**

## Troubleshooting

### If you get authentication errors:
GitHub now requires a Personal Access Token instead of passwords:
1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token with `repo` permissions
3. Use the token as your password when pushing

### If you want to use SSH instead:
```powershell
git remote set-url origin git@github.com:YOUR_USERNAME/ssh-trust-validator.git
```

## Project Structure
```
ssh-trust-validator/
├── main.py                 # CLI entry point
├── ssh_config_parser.py    # SSH config parsing
├── host_key_analyzer.py    # Host key analysis
├── dns_sshfp_query.py      # DNS SSHFP queries
├── dnssec_validator.py     # DNSSEC validation
├── trust_assessor.py        # Trust assessment logic
├── reporter.py             # Report generation
├── requirements.txt        # Dependencies
├── README.md               # Documentation
└── .gitignore             # Git ignore rules
```

## Next Steps
1. ✅ Open in VS Code
2. ✅ Push to GitHub
3. ✅ Install dependencies: `pip install -r requirements.txt`
4. ✅ Test the tool: `python main.py example.com`

Happy coding! 🚀
