package checker

import "git.happydns.org/happyDeliver/internal/feeds"

// feedStore gives the checks access to downloaded data files.
var feedStore *feeds.Store

// UseFeeds connects the checks to the feed store; call before the store runs.
func UseFeeds(store *feeds.Store) {
	feedStore = store
	watchFeeds(store)
}
