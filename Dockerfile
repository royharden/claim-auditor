FROM python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

LABEL agentports.project="m2" \
      agentports.instance="r03-rv2-e2e" \
      agentports.owner="0021_Codex_gpt-61-sol_RV2"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/claim-auditor
COPY evals/docker-requirements.txt /opt/claim-auditor/evals/docker-requirements.txt
RUN python -m pip install --no-cache-dir --no-deps -r evals/docker-requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation .
COPY evals/ evals/
USER 10001:10001
ENTRYPOINT ["python", "-m", "evals.container_check"]
CMD ["--out", "/results/public-dev"]
