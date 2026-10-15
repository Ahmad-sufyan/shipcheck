type CommentProps = {
  comment: { author: string; body: string; createdAt: string }
}

export function Comment({ comment }: CommentProps) {
  return (
    <article className="comment">
      <header>
        <strong>{comment.author}</strong> <time dateTime={comment.createdAt}>{comment.createdAt}</time>
      </header>
      {/* shipcheck-expect: INPUT-003 */}
      <div className="comment-body" dangerouslySetInnerHTML={{ __html: comment.body }} />
    </article>
  )
}
