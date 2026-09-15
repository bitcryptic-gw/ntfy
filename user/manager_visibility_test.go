package user

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManager_TopicVisibility_DefaultIsPrivate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionDenyAll, 0))

		// A newly created reservation is private by default ...
		reservations, err := a.Reservations("ben")
		require.Nil(t, err)
		require.Equal(t, 1, len(reservations))
		require.Equal(t, VisibilityPrivate, reservations[0].Visibility)

		// ... and is not listed as shared.
		shared, err := a.SharedTopics()
		require.Nil(t, err)
		require.Equal(t, 0, len(shared))
	})
}

func TestManager_TopicVisibility_SetAndListShared(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		require.Nil(t, a.AddUser("phil", "phil", RoleUser, false))
		ben, err := a.User("ben")
		require.Nil(t, err)
		phil, err := a.User("phil")
		require.Nil(t, err)
		// Underscores exercise the SQL LIKE escape/unescape round-trip.
		require.Nil(t, a.AddReservation("ben", "ben_shared", PermissionRead, 0))
		require.Nil(t, a.AddReservation("ben", "ben_private", PermissionRead, 0))
		require.Nil(t, a.AddReservation("phil", "phil_shared", PermissionRead, 0))

		visibility, owner, err := a.TopicVisibility("ben_shared")
		require.Nil(t, err)
		require.Equal(t, VisibilityPrivate, visibility)
		require.Equal(t, ben.ID, owner)

		require.Nil(t, a.SetTopicVisibility(ben.ID, "ben_shared", VisibilityShared))
		require.Nil(t, a.SetTopicVisibility(phil.ID, "phil_shared", VisibilityShared))

		shared, err := a.SharedTopics()
		require.Nil(t, err)
		require.Equal(t, 2, len(shared))
		require.Equal(t, "ben_shared", shared[0].Topic)
		require.Equal(t, "ben", shared[0].Owner)
		require.Equal(t, "phil_shared", shared[1].Topic)
		require.Equal(t, "phil", shared[1].Owner)

		// The owner's reservation reflects the new visibility ...
		reservations, err := a.Reservations("ben")
		require.Nil(t, err)
		require.Equal(t, 2, len(reservations))
		require.Equal(t, VisibilityPrivate, reservations[0].Visibility) // ben_private < ben_shared alphabetically
		require.Equal(t, VisibilityShared, reservations[1].Visibility)

		// ... and switching back to private removes it from the listing.
		require.Nil(t, a.SetTopicVisibility(ben.ID, "ben_shared", VisibilityPrivate))
		shared, err = a.SharedTopics()
		require.Nil(t, err)
		require.Equal(t, 1, len(shared))
		require.Equal(t, "phil_shared", shared[0].Topic)
	})
}

func TestManager_TopicVisibility_NonOwnerUnauthorized(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		require.Nil(t, a.AddUser("phil", "phil", RoleUser, false))
		phil, err := a.User("phil")
		require.Nil(t, err)
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionDenyAll, 0))
		require.Equal(t, ErrUnauthorized, a.SetTopicVisibility(phil.ID, "mytopic", VisibilityShared))
	})
}

func TestManager_TopicVisibility_UnknownTopic(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		visibility, owner, err := a.TopicVisibility("nope")
		require.Nil(t, err)
		require.Equal(t, Visibility(""), visibility)
		require.Equal(t, "", owner)
	})
}
