import React, { useState, useEffect } from 'react';
import { Amplify } from 'aws-amplify'; // Keep this for Amplify.configure
import { get, post, del } from 'aws-amplify/api'; // Correct way to import API methods for REST
import { fetchAuthSession, signOut as amplifySignOut } from 'aws-amplify/auth'; // Correct way to import Auth methods

import { withAuthenticator, Button, Heading, Text, TextField, View } from '@aws-amplify/ui-react';
import '@aws-amplify/ui-react/styles.css';

function App({ signOut, user }) { // The signOut prop from withAuthenticator is fine for basic sign-out
  const [bookmarks, setBookmarks] = useState([]);
  const [newBookmarkTitle, setNewBookmarkTitle] = useState('');
  const [newBookmarkUrl, setNewBookmarkUrl] = useState('');
  const [newBookmarkDescription, setNewBookmarkDescription] = useState('');

  // Function to fetch bookmarks
  async function fetchBookmarks() {
    try {
      const { tokens } = await fetchAuthSession();
      if (!tokens?.idToken) {
          console.warn("No ID token available. User might not be fully authenticated.");
          return;
      }
      const data = await get({
        apiName: 'BookmarkApi', // 'BookmarkApi' matches the name in aws-exports.js
        path: '/bookmarks',
        options: {
          headers: {
            Authorization: tokens.idToken.toString(), // Use toString() for the JWT token
          },
        },
      }).response; // .response is needed in v6 to get the actual data

      // The response from Amplify v6 API.get includes headers and a body property
      // If your Lambda returns an array directly, you might need to access data.body
      // Let's assume your lambda returns JSON directly in the body
      const responseData = await data.body.json();
      setBookmarks(responseData);

    } catch (error) {
      console.error('Error fetching bookmarks:', error);
      // Handle unauthorized errors specifically, e.g., redirect to login
      if (error.response && error.response.status === 401) {
          console.log("Unauthorized, attempting sign out.");
          amplifySignOut(); // Use the imported amplifySignOut function
      }
    }
  }

  // Function to add a new bookmark
  async function addBookmark() {
    if (!newBookmarkTitle || !newBookmarkUrl) return;

    try {
      const { tokens } = await fetchAuthSession();
      if (!tokens?.idToken) {
          console.warn("No ID token available. User might not be fully authenticated.");
          return;
      }
      const bookmark = {
        title: newBookmarkTitle,
        url: newBookmarkUrl,
        description: newBookmarkDescription,
      };

      await post({
        apiName: 'BookmarkApi',
        path: '/bookmarks',
        options: {
          body: bookmark,
          headers: {
            Authorization: tokens.idToken.toString(),
          },
        },
      }).response; // .response is needed in v6

      setNewBookmarkTitle('');
      setNewBookmarkUrl('');
      setNewBookmarkDescription('');
      fetchBookmarks(); // Refresh the list
    } catch (error) {
      console.error('Error adding bookmark:', error);
      if (error.response && error.response.status === 401) {
          console.log("Unauthorized, attempting sign out.");
          amplifySignOut();
      }
    }
  }

  // Function to delete a bookmark
  async function deleteBookmark(bookmarkId) {
    try {
      const { tokens } = await fetchAuthSession();
      if (!tokens?.idToken) {
          console.warn("No ID token available. User might not be fully authenticated.");
          return;
      }
      await del({
        apiName: 'BookmarkApi',
        path: `/bookmarks/${bookmarkId}`,
        options: {
          headers: {
            Authorization: tokens.idToken.toString(),
          },
        },
      }).response; // .response is needed in v6
      fetchBookmarks(); // Refresh the list
    } catch (error) {
      console.error('Error deleting bookmark:', error);
      if (error.response && error.response.status === 401) {
          console.log("Unauthorized, attempting sign out.");
          amplifySignOut();
      }
    }
  }

  useEffect(() => {
    // Only attempt to fetch bookmarks if a user is available (i.e., authenticated)
    if (user) {
      fetchBookmarks();
    }
  }, [user]); // Re-run effect when 'user' object changes (e.g., after login)

  return (
    <View style={styles.container}>
      <Heading level={1} style={styles.header}>
        Hello {user.username}!
      </Heading>
      <Button onClick={signOut} style={styles.signOutButton}>Sign Out</Button>

      <Heading level={2} style={styles.sectionHeader}>Your Bookmarks</Heading>
      <View style={styles.addBookmarkSection}>
        <TextField
          placeholder="Bookmark Title"
          value={newBookmarkTitle}
          onChange={(e) => setNewBookmarkTitle(e.target.value)}
          style={styles.inputField}
        />
        <TextField
          placeholder="Bookmark URL (e.g., https://example.com)"
          value={newBookmarkUrl}
          onChange={(e) => setNewBookmarkUrl(e.target.value)}
          style={styles.inputField}
        />
        <TextField
          placeholder="Description (Optional)"
          value={newBookmarkDescription}
          onChange={(e) => setNewBookmarkDescription(e.target.value)}
          style={styles.inputField}
        />
        <Button onClick={addBookmark} style={styles.addButton}>Add Bookmark</Button>
      </View>

      <View style={styles.bookmarkList}>
        {bookmarks.length === 0 ? (
          <Text>No bookmarks yet. Add one above!</Text>
        ) : (
          bookmarks.map((bookmark) => (
            <View key={bookmark.bookmarkId} style={styles.bookmarkItem}>
              <Text style={styles.bookmarkTitle}>{bookmark.title}</Text>
              <a href={bookmark.url} target="_blank" rel="noopener noreferrer" style={styles.bookmarkUrl}>{bookmark.url}</a>
              {bookmark.description && <Text style={styles.bookmarkDescription}>{bookmark.description}</Text>}
              <Button onClick={() => deleteBookmark(bookmark.bookmarkId)} size="small" variation="destructive" style={styles.deleteButton}>
                Delete
              </Button>
            </View>
          ))
        )}
      </View>
    </View>
  );
}

const styles = {
  container: {
    padding: '20px',
    maxWidth: '800px',
    margin: '0 auto',
    fontFamily: 'Arial, sans-serif',
  },
  header: {
    textAlign: 'center',
    marginBottom: '20px',
  },
  signOutButton: {
    display: 'block',
    margin: '0 auto 30px auto',
  },
  sectionHeader: {
    marginTop: '40px',
    marginBottom: '20px',
    borderBottom: '1px solid #eee',
    paddingBottom: '10px',
  },
  addBookmarkSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
    marginBottom: '30px',
    padding: '20px',
    border: '1px solid #ddd',
    borderRadius: '8px',
    backgroundColor: '#f9f9f9',
  },
  inputField: {
    marginBottom: '5px',
  },
  addButton: {
    marginTop: '10px',
    backgroundColor: '#007bff',
    color: 'white',
  },
  bookmarkList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '15px',
  },
  bookmarkItem: {
    border: '1px solid #eee',
    padding: '15px',
    borderRadius: '8px',
    backgroundColor: '#fff',
    boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
    position: 'relative',
  },
  bookmarkTitle: {
    fontSize: '1.2em',
    fontWeight: 'bold',
    marginBottom: '5px',
    color: '#333',
  },
  bookmarkUrl: {
    color: '#007bff',
    textDecoration: 'none',
    fontSize: '0.9em',
  },
  bookmarkDescription: {
    fontSize: '0.9em',
    color: '#666',
    marginTop: '5px',
  },
  deleteButton: {
    marginTop: '10px',
    backgroundColor: '#dc3545',
    color: 'white',
  }
};

export default withAuthenticator(App);