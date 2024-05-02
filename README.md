# Multi-Threaded HTTP Server

### Overview
This project implements a multi-threaded HTTP server designed to handle multiple client requests simultaneously through effective use of concurrency. Combining robust synchronization mechanisms with a dynamic threading model, the server ensures efficient hardware utilization while maintaining a coherent and atomic response behavior as expected from a single-threaded server.

### Features
- **Concurrent Handling**: Supports multiple clients at once using a fixed number of worker threads.
- **Thread-Safe Queue**: Integrates a thread-safe queue to manage incoming requests effectively.
- **Audit Log**: Generates a comprehensive audit log to stderr, detailing the sequence and specifics of client requests handled, ensuring transparency and traceability.
- **Dynamic Request Handling**: Uses a dispatcher thread to efficiently allocate tasks to worker threads without idling resources.

### How It Works
1. **Command Line Interface**: The server is started with user-defined settings for the port and the number of threads, with sensible defaults in place.
   ```bash
   ./httpserver [-t threads] <port>
   ```
2. **Thread Pool Architecture**: Utilizes a pool of worker threads that process requests and a dispatcher thread that assigns incoming requests to workers.
3. **Synchronization**: Implements synchronization to manage access to shared resources among threads, ensuring data integrity and response accuracy.

### Technical Setup
- **Tools Used**: Developed in a C programming environment, leveraging standard libraries and advanced synchronization primitives from pthreads.
- **Environment**: Optimized and tested on UNIX-based systems for robust performance and stability.

### Challenges Overcome
- **Concurrency Management**: Mastering the synchronization needed to handle concurrent accesses and modifications without sacrificing performance.
- **Resource Management**: Ensuring that the server runs efficiently without memory leaks or excessive resource consumption.

### Accomplishments
- **High Throughput**: Achieved significant improvements in server throughput without compromising the response integrity.
- **Reliable Logging**: Implemented a reliable and atomic logging mechanism that withstands system interruptions and provides accurate playback of events.

### Future Directions
- Further enhancements will focus on scalability, including the integration of more advanced load balancing techniques and the exploration of asynchronous I/O operations to boost performance.

### Usage
- Compile the server using the provided Makefile.
- Run the server specifying the port and optionally the number of worker threads.
- Monitor the stderr for the audit log output.

