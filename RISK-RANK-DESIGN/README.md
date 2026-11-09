# RiskRank-VAPT — Web Dashboard

A static, client-side dashboard for reviewing the scored vulnerability
output of the [RiskRank-VAPT](../README.md) Python pipeline. Upload the
pipeline's exported CSV (`results/reports/prioritized_cves.csv` or
`evaluation_metrics.csv`) — nothing is recalculated, parsed, or sent to any
server; see the parent [README](../README.md#web-dashboard-risk-rank-design)
for setup, data format and deployment notes.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Open your project in the [Lovable editor](https://lovable.dev) and keep building.

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: connect the project to GitHub and every change made in Lovable is committed straight to your repository.
- **Full ownership**: this code is yours. Push to your repository and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## Built with

- TanStack Start
- TypeScript
- React
- Tailwind CSS
