import ReactMarkdown from 'react-markdown'
import rehypeRaw from 'rehype-raw'

export function MarkdownView({ source }: { source: string }) {
  // shipcheck-expect: INPUT-004
  return <ReactMarkdown rehypePlugins={[rehypeRaw]}>{source}</ReactMarkdown>
}
