package user

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"heckel.io/ntfy/v2/db/schema"
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

// TestMigration9To10_BackfillsExistingReservationsAsPrivate verifies that migrating a v9 database
// creates a topics row for every pre-existing reservation (owner row) as 'private', and does not
// create rows for plain ACL grants or the paired Everyone row.
func TestMigration9To10_BackfillsExistingReservationsAsPrivate(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "user.db")
	d, err := sql.Open("sqlite3", filename)
	require.Nil(t, err)
	defer d.Close()
	_, err = d.Exec(`
		BEGIN;
		CREATE TABLE user (id TEXT PRIMARY KEY, user TEXT NOT NULL);
		CREATE TABLE user_access (
			user_id TEXT NOT NULL,
			topic TEXT NOT NULL,
			read INT NOT NULL,
			write INT NOT NULL,
			owner_user_id INT,
			PRIMARY KEY (user_id, topic)
		);
		CREATE TABLE schemaVersion (id INT PRIMARY KEY, version INT NOT NULL);
		INSERT INTO user (id, user) VALUES ('u_ben', 'ben');
		INSERT INTO user (id, user) VALUES ('u_everyone', '*');
		INSERT INTO user_access VALUES ('u_ben', 'my\_topic', 1, 1, 'u_ben');       -- reservation owner row
		INSERT INTO user_access VALUES ('u_everyone', 'my\_topic', 0, 0, 'u_ben');  -- paired Everyone row
		INSERT INTO user_access VALUES ('u_everyone', 'other', 1, 1, NULL);         -- plain ACL grant
		INSERT INTO schemaVersion VALUES (1, 9);
		COMMIT;
	`)
	require.Nil(t, err)
	require.Nil(t, schema.Migrate(d, schema.SQLite, "user", 10, sqliteCreateTables, sqliteMigrations))

	var topic, owner, visibility string
	require.Nil(t, d.QueryRow(`SELECT topic, owner_user_id, visibility FROM topics`).Scan(&topic, &owner, &visibility))
	require.Equal(t, `my\_topic`, topic) // topics uses the same escaped representation as user_access.topic
	require.Equal(t, "u_ben", owner)
	require.Equal(t, "private", visibility)

	var count int
	require.Nil(t, d.QueryRow(`SELECT COUNT(*) FROM topics`).Scan(&count))
	require.Equal(t, 1, count)
}

// TestManager_TopicVisibility_RemovedWithReservation verifies the topics row follows the
// reservation through removal: deleting the reservation deletes the entity, and a later
// re-reservation starts fresh (private).
func TestManager_TopicVisibility_RemovedWithReservation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		ben, err := a.User("ben")
		require.Nil(t, err)
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionDenyAll, 0))
		require.Nil(t, a.SetTopicVisibility(ben.ID, "mytopic", VisibilityShared))

		require.Nil(t, a.RemoveReservations("ben", "mytopic"))
		visibility, owner, err := a.TopicVisibility("mytopic")
		require.Nil(t, err)
		require.Equal(t, Visibility(""), visibility)
		require.Equal(t, "", owner)
		shared, err := a.SharedTopics()
		require.Nil(t, err)
		require.Equal(t, 0, len(shared))

		// Re-reserving creates a fresh, private entity.
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionDenyAll, 0))
		visibility, owner, err = a.TopicVisibility("mytopic")
		require.Nil(t, err)
		require.Equal(t, VisibilityPrivate, visibility)
		require.Equal(t, ben.ID, owner)
	})
}

// TestManager_TopicVisibility_FullAccessResetClearsTopics verifies a full ACL reset also clears
// the topics entities, so no orphaned reservations are left behind.
func TestManager_TopicVisibility_FullAccessResetClearsTopics(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		ben, err := a.User("ben")
		require.Nil(t, err)
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionDenyAll, 0))
		require.Nil(t, a.SetTopicVisibility(ben.ID, "mytopic", VisibilityShared))

		require.Nil(t, a.ResetAccess("", ""))
		visibility, owner, err := a.TopicVisibility("mytopic")
		require.Nil(t, err)
		require.Equal(t, Visibility(""), visibility)
		require.Equal(t, "", owner)
	})
}

// TestManager_TopicVisibility_ReservedNameCannotBeReserved verifies the "~" system-topic prefix
// is rejected by the normal reservation path, so a user can never claim the directory topic.
func TestManager_TopicVisibility_ReservedNameCannotBeReserved(t *testing.T) {
	require.False(t, AllowedTopic("~directory"))
	require.False(t, AllowedTopic("~control"))
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		require.Equal(t, ErrInvalidArgument, a.AddReservation("ben", "~directory", PermissionDenyAll, 0))
	})
}

// TestManager_TopicVisibility_PreservedOnReReservation verifies that re-adding an existing
// reservation (e.g. to change the Everyone permission) does not reset a shared topic to private.
func TestManager_TopicVisibility_PreservedOnReReservation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		require.Nil(t, a.AddUser("ben", "ben", RoleUser, false))
		ben, err := a.User("ben")
		require.Nil(t, err)
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionDenyAll, 0))
		require.Nil(t, a.SetTopicVisibility(ben.ID, "mytopic", VisibilityShared))

		// Re-add with a different Everyone permission, then confirm it is still shared.
		require.Nil(t, a.AddReservation("ben", "mytopic", PermissionRead, 0))
		visibility, owner, err := a.TopicVisibility("mytopic")
		require.Nil(t, err)
		require.Equal(t, VisibilityShared, visibility)
		require.Equal(t, ben.ID, owner)
	})
}
