FROM --platform=amd64 ubuntu:22.04

# Note: this installs zsh and oh-my-zsh and sets them as the default shell for
# the user. This is more or less subjective which shell to use and zsh seemed
# like a safe bet.
# Since this dockerfile is only used for development and not deployment it
# seemed reasonable to install these niceties for developers.
RUN  apt-get update \
  && apt-get install -y \
     build-essential curl git wget libclang-14-dev sudo vim zsh \
  && apt-get clean \
  && rm -r /var/lib/apt/lists

# Install SGX_SDK
ARG SGX_URL=https://download.01.org/intel-sgx/sgx-linux/2.23/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.23.100.2.bin
RUN  curl -o sgx.bin "${SGX_URL}" \
  && chmod +x ./sgx.bin \
  && ./sgx.bin --prefix=/opt/intel \
  && rm ./sgx.bin

# Install DCAP libraries
ARG DCAP_VERSION=1.20.100.2-jammy1
RUN mkdir -p /etc/apt/keyrings \
  && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor | tee /etc/apt/keyrings/intel-sgx.gpg > /dev/null \
  && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" | tee /etc/apt/sources.list.d/intel-sgx.list \
  && apt-get update \
  && apt-get install -y \
     libsgx-dcap-ql=${DCAP_VERSION} \
     libsgx-dcap-ql-dev=${DCAP_VERSION} \
     libsgx-dcap-quote-verify=${DCAP_VERSION} \
     libsgx-dcap-quote-verify-dev=${DCAP_VERSION} \
  && apt-get clean \
  && rm -r /var/lib/apt/lists

# We create a user for the container. The name will be `docker`
ARG USERNAME=docker
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
  && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
  && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME \
  && chsh -s /usr/bin/zsh $USERNAME

USER $USERNAME

# install oh-my-zsh
RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN echo "[ -f /opt/intel/sgxsdk/environment ] && . /opt/intel/sgxsdk/environment" >> ~/.zshenv