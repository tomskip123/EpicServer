# EpicServer Documentation

This directory contains the documentation for EpicServer, built with [Hugo](https://gohugo.io/) and the [Doks](https://getdoks.org/) theme.

## Local Development

### Prerequisites

- Node.js 20.x or later
- Hugo Extended 0.145.0 or later

### Setup

1. Install dependencies:

```bash
npm install
```

2. Start the development server:

```bash
npm run dev
```

This will start a local development server at http://localhost:1313.

## Building for Production

To build the documentation for production:

```bash
npm run build
```

This will generate the static site in the `public` directory.

## Deployment

The documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch. The deployment is handled by a GitHub Actions workflow defined in `.github/workflows/deploy-docs.yml`.

### Manual Deployment

You can also trigger a manual deployment by going to the Actions tab in the GitHub repository and selecting the "Deploy Documentation to GitHub Pages" workflow, then clicking "Run workflow".

## Documentation Structure

- `content/`: Contains all the documentation content in Markdown format
  - `docs/`: Main documentation content
    - `getting-started/`: Quick start and installation guides
    - `guides/`: How-to guides for various features
    - `reference/`: API reference and technical details
    - `concepts/`: Conceptual explanations
    - `examples/`: Example code and use cases
- `static/`: Static assets like images
- `layouts/`: Custom Hugo layouts (if any)
- `config/`: Hugo configuration files

## Adding New Content

To add a new page to the documentation:

1. Create a new Markdown file in the appropriate directory under `content/docs/`
2. Add the required front matter at the top of the file:

```yaml
---
title: "Page Title"
description: "Brief description of the page"
summary: "A summary of the page content"
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 10
toc: true
seo:
  title: "Custom SEO Title (optional)"
  description: "Custom SEO description (recommended)"
---
```

3. Add your content in Markdown format below the front matter

## Contributing to Documentation

When contributing to the documentation, please follow these guidelines:

1. Use clear, concise language
2. Include code examples where appropriate
3. Keep the documentation up-to-date with the latest version of EpicServer
4. Test any code examples to ensure they work as expected
5. Preview your changes locally before submitting a pull request 