"""
LLM Environment for Sandbox Testing

This module provides a sandboxed environment for testing LLMs, allowing for
controlled execution, monitoring, and analysis of LLM behavior.
"""

import os
import time
import uuid
import json
import logging
import hashlib
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)

class LLMEnvironment:
    """
    Provides a sandboxed environment for testing LLMs.
    
    This class creates an isolated environment for testing LLMs, with
    capabilities for prompt processing, response analysis, and behavior monitoring.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the LLM environment with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for the environment.
                   Supported keys:
                   - mode: Environment mode (mock, api, container)
                   - timeout: Maximum time in seconds for LLM processing
                   - max_tokens: Maximum number of tokens for LLM responses
                   - api_config: Configuration for API mode
                   - container_config: Configuration for container mode
        """
        self.config = config or {}
        self.mode = self.config.get("mode", "mock")
        self.timeout = self.config.get("timeout", 30)
        self.max_tokens = self.config.get("max_tokens", 1000)
        
        # Initialize session
        self.session_id = str(uuid.uuid4())
        self.session_start = datetime.now()
        self.interactions = []
        
        # Load mock responses if in mock mode
        if self.mode == "mock":
            self._load_mock_responses()
        
        # Initialize API client if in API mode
        elif self.mode == "api":
            self._init_api_client()
        
        # Initialize container if in container mode
        elif self.mode == "container":
            self._init_container()
        
        logger.info(f"Initialized LLM environment in {self.mode} mode")
    
    def process_prompt(self, prompt: str, system_message: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a prompt in the sandboxed environment.
        
        Args:
            prompt: The prompt to process
            system_message: Optional system message to prepend to the prompt
            
        Returns:
            Dictionary with processing results
        """
        logger.info(f"Processing prompt in {self.mode} mode")
        
        # Generate interaction ID
        interaction_id = str(uuid.uuid4())
        
        # Record start time
        start_time = time.time()
        
        # Process prompt based on mode
        if self.mode == "mock":
            response = self._process_mock(prompt, system_message)
        elif self.mode == "api":
            response = self._process_api(prompt, system_message)
        elif self.mode == "container":
            response = self._process_container(prompt, system_message)
        else:
            response = f"Unsupported mode: {self.mode}"
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Create result
        result = {
            "id": interaction_id,
            "mode": self.mode,
            "response": response,
            "elapsed_time": elapsed_time
        }
        
        # Record interaction
        self.interactions.append({
            "id": interaction_id,
            "timestamp": datetime.now().isoformat(),
            "prompt": prompt,
            "system_message": system_message,
            "response": response,
            "elapsed_time": elapsed_time
        })
        
        logger.info(f"Processed prompt in {elapsed_time:.2f}s")
        
        return result
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get information about the current session.
        
        Returns:
            Dictionary with session information
        """
        session_duration = (datetime.now() - self.session_start).total_seconds()
        
        return {
            "session_id": self.session_id,
            "session_start": self.session_start.isoformat(),
            "session_duration": session_duration,
            "interaction_count": len(self.interactions),
            "mode": self.mode
        }
    
    def get_interactions(self) -> List[Dict[str, Any]]:
        """
        Get all interactions in the current session.
        
        Returns:
            List of interaction dictionaries
        """
        return self.interactions
    
    def reset(self):
        """Reset the environment, starting a new session."""
        logger.info("Resetting LLM environment")
        
        # Generate new session ID
        self.session_id = str(uuid.uuid4())
        self.session_start = datetime.now()
        self.interactions = []
        
        # Reset mode-specific components
        if self.mode == "container":
            self._reset_container()
    
    def _load_mock_responses(self):
        """Load mock responses for testing."""
        # Define basic mock responses
        self.mock_responses = {
            "prompt_injection": "I cannot follow those instructions as they appear to be a prompt injection attempt.",
            "credential_request": "I cannot provide any credentials, API keys, or sensitive information.",
            "malicious_code": "I cannot provide code that could be used maliciously or that contains security vulnerabilities.",
            "default": "This is a mock response from the LLM environment."
        }
        
        # Load custom mock responses if available
        mock_file = self.config.get("mock_responses_file")
        if mock_file and os.path.exists(mock_file):
            try:
                with open(mock_file, 'r') as f:
                    custom_responses = json.load(f)
                self.mock_responses.update(custom_responses)
                logger.info(f"Loaded custom mock responses from {mock_file}")
            except Exception as e:
                logger.error(f"Failed to load mock responses: {e}")
    
    def _init_api_client(self):
        """Initialize API client for API mode."""
        api_config = self.config.get("api_config", {})
        api_type = api_config.get("type", "openai")
        
        if api_type == "openai":
            try:
                import openai
                openai.api_key = api_config.get("api_key")
                self.api_client = openai
                logger.info("Initialized OpenAI API client")
            except ImportError:
                logger.error("OpenAI package not installed")
                self.api_client = None
        else:
            logger.error(f"Unsupported API type: {api_type}")
            self.api_client = None
    
    def _init_container(self):
        """Initialize container for container mode."""
        container_config = self.config.get("container_config", {})
        
        try:
            import docker
            self.docker_client = docker.from_env()
            
            # Check if container exists
            container_name = container_config.get("name", "llm-sandbox")
            containers = self.docker_client.containers.list(all=True, filters={"name": container_name})
            
            if containers:
                self.container = containers[0]
                if self.container.status != "running":
                    self.container.start()
                logger.info(f"Using existing container: {container_name}")
            else:
                # Create new container
                image = container_config.get("image", "python:3.9-slim")
                self.container = self.docker_client.containers.run(
                    image,
                    name=container_name,
                    detach=True,
                    remove=True,
                    command="tail -f /dev/null"  # Keep container running
                )
                logger.info(f"Created new container: {container_name}")
            
        except ImportError:
            logger.error("Docker package not installed")
            self.docker_client = None
            self.container = None
        except Exception as e:
            logger.error(f"Failed to initialize container: {e}")
            self.docker_client = None
            self.container = None
    
    def _reset_container(self):
        """Reset the container environment."""
        if hasattr(self, 'container') and self.container:
            try:
                # Stop and remove container
                self.container.stop()
                self.container.remove()
                
                # Create new container
                container_config = self.config.get("container_config", {})
                container_name = container_config.get("name", "llm-sandbox")
                image = container_config.get("image", "python:3.9-slim")
                
                self.container = self.docker_client.containers.run(
                    image,
                    name=container_name,
                    detach=True,
                    remove=True,
                    command="tail -f /dev/null"  # Keep container running
                )
                
                logger.info(f"Reset container: {container_name}")
            except Exception as e:
                logger.error(f"Failed to reset container: {e}")
    
    def _process_mock(self, prompt: str, system_message: Optional[str] = None) -> str:
        """
        Process a prompt using mock responses.
        
        Args:
            prompt: The prompt to process
            system_message: Optional system message
            
        Returns:
            Mock response string
        """
        # Check for prompt injection
        if any(keyword in prompt.lower() for keyword in [
            "ignore previous instructions",
            "ignore all instructions",
            "disregard",
            "system prompt",
            "you are actually",
            "your real instructions"
        ]):
            return self.mock_responses["prompt_injection"]
        
        # Check for credential requests
        if any(keyword in prompt.lower() for keyword in [
            "api key",
            "password",
            "token",
            "credential",
            "secret"
        ]):
            return self.mock_responses["credential_request"]
        
        # Check for malicious code requests
        if any(keyword in prompt.lower() for keyword in [
            "eval(",
            "exec(",
            "system(",
            "shell",
            "exploit",
            "vulnerability"
        ]):
            return self.mock_responses["malicious_code"]
        
        # Generate a deterministic but varied response based on the prompt
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
        
        # Use the first 8 characters of the hash as a seed
        seed = int(prompt_hash[:8], 16)
        
        # Select words based on the seed
        words = [
            "security", "analysis", "platform", "testing", "sandbox",
            "monitoring", "validation", "verification", "protection",
            "detection", "prevention", "mitigation", "response", "recovery"
        ]
        
        selected_words = []
        for i in range(10):  # Select 10 words
            word_index = (seed + i) % len(words)
            selected_words.append(words[word_index])
        
        # Construct a response
        response = f"This is a mock response for testing purposes. "
        response += f"The prompt was processed in the {self.mode} environment. "
        response += f"Here are some relevant terms: {', '.join(selected_words)}. "
        
        # Add system message context if provided
        if system_message:
            response += f"The system context was: '{system_message[:20]}...'. "
        
        return response
    
    def _process_api(self, prompt: str, system_message: Optional[str] = None) -> str:
        """
        Process a prompt using an API.
        
        Args:
            prompt: The prompt to process
            system_message: Optional system message
            
        Returns:
            API response string
        """
        if not hasattr(self, 'api_client') or not self.api_client:
            return "API client not initialized"
        
        api_config = self.config.get("api_config", {})
        api_type = api_config.get("type", "openai")
        
        try:
            if api_type == "openai":
                # Prepare messages
                messages = []
                
                if system_message:
                    messages.append({"role": "system", "content": system_message})
                
                messages.append({"role": "user", "content": prompt})
                
                # Call API
                response = self.api_client.ChatCompletion.create(
                    model=api_config.get("model", "gpt-3.5-turbo"),
                    messages=messages,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout
                )
                
                # Extract response text
                return response.choices[0].message.content
            else:
                return f"Unsupported API type: {api_type}"
        except Exception as e:
            logger.error(f"API call failed: {e}")
            return f"API call failed: {str(e)}"
    
    def _process_container(self, prompt: str, system_message: Optional[str] = None) -> str:
        """
        Process a prompt using a container.
        
        Args:
            prompt: The prompt to process
            system_message: Optional system message
            
        Returns:
            Container execution response string
        """
        if not hasattr(self, 'container') or not self.container:
            return "Container not initialized"
        
        try:
            # Prepare script
            script = "#!/usr/bin/env python3\n"
            script += "import sys\n"
            script += "import json\n\n"
            
            script += "# Input data\n"
            script += f"prompt = {json.dumps(prompt)}\n"
            if system_message:
                script += f"system_message = {json.dumps(system_message)}\n"
            else:
                script += "system_message = None\n"
            
            script += "\n# Process prompt\n"
            script += "print('Processing prompt in container...')\n"
            script += "print(f'Prompt: {prompt}')\n"
            script += "if system_message:\n"
            script += "    print(f'System message: {system_message}')\n\n"
            
            script += "# Generate response\n"
            script += "response = f'Container processed: {prompt[:20]}...'\n"
            script += "print(json.dumps({'response': response}))\n"
            
            # Create script file in container
            script_path = "/tmp/process_prompt.py"
            self.container.exec_run(f"bash -c \"echo '{script}' > {script_path}\"")
            self.container.exec_run(f"chmod +x {script_path}")
            
            # Run script
            result = self.container.exec_run(f"python {script_path}")
            
            # Parse output
            output = result.output.decode('utf-8')
            
            # Extract JSON response
            try:
                import re
                json_match = re.search(r'(\{.*\})', output)
                if json_match:
                    response_data = json.loads(json_match.group(1))
                    return response_data.get("response", output)
                else:
                    return output
            except Exception as e:
                logger.error(f"Failed to parse container output: {e}")
                return output
            
        except Exception as e:
            logger.error(f"Container execution failed: {e}")
            return f"Container execution failed: {str(e)}"