# Setting Up GitHub Pages for EpicServer Documentation

This guide explains how to set up GitHub Pages to host the EpicServer documentation.

## Prerequisites

- You must have admin access to the GitHub repository
- GitHub Actions must be enabled for the repository

## Steps to Enable GitHub Pages

1. Go to your GitHub repository at `https://github.com/tomskip123/EpicServer`
2. Click on "Settings" in the top navigation bar
3. In the left sidebar, click on "Pages"
4. Under "Build and deployment", select the following settings:
   - Source: "GitHub Actions"
   - (The actual deployment is handled by the workflow in `.github/workflows/deploy-docs.yml`)
5. Click "Save"

## Verifying the Setup

1. Go to the "Actions" tab in your repository
2. You should see the "Deploy Documentation to GitHub Pages" workflow
3. If it hasn't run automatically, click on "Run workflow" and select the main branch
4. Once the workflow completes successfully, your documentation will be available at `https://tomskip123.github.io/EpicServer/`

## Troubleshooting

If you encounter issues with the deployment:

1. Check the workflow logs in the Actions tab for any errors
2. Ensure that the repository has the correct permissions set for GitHub Actions
3. Verify that the `baseurl` in `docs/config/_default/hugo.toml` is set correctly to `https://tomskip123.github.io/EpicServer/`
4. Make sure the GitHub Pages settings are configured to use GitHub Actions as the source

## Manual Deployment

You can manually trigger a deployment by:

1. Going to the "Actions" tab in your repository
2. Clicking on the "Deploy Documentation to GitHub Pages" workflow
3. Clicking "Run workflow" and selecting the main branch

## Updating the Documentation

Any changes pushed to the `docs/` directory in the main branch will automatically trigger a new deployment. The workflow is configured to only run when changes are made to the `docs/` directory or the workflow file itself. 