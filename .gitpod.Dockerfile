FROM gitpod/workspace-full

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && sudo ./aws/install \
    && rm -rf aws awscliv2.zip

# Install jq for JSON parsing (used in deployment scripts)
RUN sudo apt-get update \
    && sudo apt-get install -y jq \
    && sudo rm -rf /var/lib/apt/lists/*
