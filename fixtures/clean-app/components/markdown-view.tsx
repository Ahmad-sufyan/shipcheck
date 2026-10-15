import ReactMarkdown from 'react-markdown'
import rehypeRaw from 'rehype-raw'
import rehypeSanitize from 'rehype-sanitize'

export function MarkdownView({ source }: { source: string }) {
  return <ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>{source}</ReactMarkdown>
}
