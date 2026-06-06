/**
 * Random Joke Generator
 * Fetches jokes from JokeAPI and displays them in the console
 * 
 * API: https://jokeapi.dev
 * Supports single-part and two-part jokes with filtering options
 */

const https = require('https');

/**
 * Fetches a random joke from JokeAPI
 * @param {Object} options - Configuration options
 * @param {string} options.type - 'single' or 'twopart' (default: any)
 * @param {string} options.category - Joke category: 'general', 'knock-knock', 'programming', 'misc', 'dark', 'spooky' (default: any)
 * @param {boolean} options.safe - Filter to safe jokes only (default: true)
 * @returns {Promise<Object>} Joke object
 */
function getRandomJoke(options = {}) {
  return new Promise((resolve, reject) => {
    const {
      type = 'any',
      category = 'any',
      safe = true
    } = options;

    // Build query parameters
    const params = new URLSearchParams();
    if (type !== 'any') params.append('type', type);
    if (category !== 'any') params.append('category', category);
    if (!safe) params.append('safe-mode', 'false');

    const url = `https://v2.jokeapi.dev/joke/${category}${params.toString() ? '?' + params.toString() : ''}`;

    https.get(url, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const joke = JSON.parse(data);

          if (joke.error) {
            reject(new Error(`API Error: ${joke.message}`));
          } else {
            resolve(joke);
          }
        } catch (error) {
          reject(new Error(`Failed to parse API response: ${error.message}`));
        }
      });
    }).on('error', (error) => {
      reject(new Error(`Network error: ${error.message}`));
    });
  });
}

/**
 * Formats and displays a joke
 * @param {Object} joke - Joke object from API
 */
function displayJoke(joke) {
  console.log('\n' + '='.repeat(60));
  
  if (joke.type === 'single') {
    console.log(`📝 Joke:\n${joke.joke}`);
  } else if (joke.type === 'twopart') {
    console.log(`📝 Setup:\n${joke.setup}\n`);
    console.log(`😂 Punchline:\n${joke.delivery}`);
  }

  console.log('\n' + `Category: ${joke.category}`);
  console.log('='.repeat(60) + '\n');
}

/**
 * Main function - fetches and displays random jokes
 */
async function main() {
  console.log('🎭 Welcome to the Random Joke Generator!\n');

  try {
    // Example 1: Get any random joke
    console.log('Fetching a random joke...');
    const joke1 = await getRandomJoke();
    displayJoke(joke1);

    // Example 2: Get a programming joke
    console.log('Fetching a programming joke...');
    const joke2 = await getRandomJoke({ category: 'programming', safe: true });
    displayJoke(joke2);

    // Example 3: Get a knock-knock joke
    console.log('Fetching a knock-knock joke...');
    const joke3 = await getRandomJoke({ category: 'knock-knock', type: 'twopart' });
    displayJoke(joke3);

  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

// Run the joke generator
main();
