# GlassWall AI

## Overview

GlassWall AI is an enterprise Zero-Trust Optical Data Loss Prevention (ODLP) platform designed to secure sensitive data across various environments, including banking, healthcare, government, defense, and high-security remote work settings. The platform employs advanced threat detection and response mechanisms to ensure data integrity and confidentiality.

## Project Structure

The project is organized into the following directories:

- **app/api/**: Contains FastAPI routes and endpoints for client-server communication.
- **app/auth/**: Manages authentication mechanisms, including JWT management and user verification.
- **app/core/**: Houses core functionalities and shared components utilized across various modules.
- **app/dependencies/**: Defines dependency injection configurations and shared services.
- **app/services/**: Contains business logic and service layer implementations interacting with core components and external services.
- **app/websocket/**: Manages WebSocket connections and real-time data streaming functionalities.
- **tests/**: Contains unit tests, integration tests, and performance tests for all modules, ensuring high test coverage and reliability.

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/glasswall-ai.git
   cd glasswall-ai
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   You can run the application using Docker:
   ```bash
   docker-compose up --build
   ```

## Usage Guidelines

- Access the API documentation at `/docs` after starting the FastAPI server.
- Use the WebSocket endpoints for real-time data streaming and interaction.

## Contribution

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch and create a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.