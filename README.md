This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

## Environment Variables

Set `NEXT_PUBLIC_GTM_CONTAINER_ID` (format: `GTM-XXXXXXX`) to embed Google Tag Manager during build.

```bash
NEXT_PUBLIC_GTM_CONTAINER_ID=GTM-XXXXXXX
```

If this variable is not set, GTM tags are not included.

## RC-S380 接続時のトラブルシューティング

### `Failed to execute 'open' on 'USBDevice': Access denied.` が出る

以下を順に確認してください。

1. RC-S380 を使用している他アプリ（NFCポートソフト、カードビューア、e-Tax関連ソフトなど）を終了する
2. RC-S380 を抜き差ししてから、ブラウザ（Chrome / Edge）を再起動する
3. Windows の場合、RC-S380 が WebUSB で利用可能なドライバー（WinUSB）になっているか確認する

## 読み取りできる情報

- カード識別情報（IDm / PMm / システムコード）
- 追加情報（カードモード、利用可能システムコード）
- 交通系履歴（サービスコード `090F`、最大20件）

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
