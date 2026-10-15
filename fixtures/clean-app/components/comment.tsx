import DOMPurify from 'isomorphic-dompurify'

type CommentProps = {
  comment: { author: string; body: string; createdAt: string }
}

export function Comment({ comment }: CommentProps) {
  const safeBody = DOMPurify.sanitize(comment.body, { USE_PROFILES: { html: true } })
  return (
    <article className="comment">
      <header>
        <strong>{comment.author}</strong> <time dateTime={comment.createdAt}>{comment.createdAt}</time>
      </header>
      <div className="comment-body" dangerouslySetInnerHTML={{ __html: safeBody }} />
    </article>
  )
}
