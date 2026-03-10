# warrant-shell end-to-end test runtime image
# Build context is prepared by e2e/run.sh and includes only:
#   - wsh
#   - wsh-auditd
#   - test-*.sh

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git ca-certificates sudo openssl jq \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash agent \
    && echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/agent \
    && echo 'Defaults env_keep += "PATH HOME"' > /etc/sudoers.d/env

RUN npm install -g @anthropic-ai/claude-code @openai/codex 2>/dev/null || true

COPY wsh /usr/local/bin/wsh
COPY wsh-auditd /usr/local/bin/wsh-auditd
RUN chmod +x /usr/local/bin/wsh /usr/local/bin/wsh-auditd

USER agent
WORKDIR /home/agent

COPY --chown=agent:agent test-*.sh /home/agent/tests/
RUN sudo chmod +x /home/agent/tests/*.sh

ENTRYPOINT ["/bin/bash"]
