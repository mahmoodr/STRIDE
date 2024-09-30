Securing K8s based on STRIDE Treat Modeling:

1. Spoofing (Pretending to be somebody else with the aim of gaining extra privileges):
	· Securing cluster with authentication and authorization (robust RBAC)
	· Securing communications with the API server:
        • Ensure that certificates issued by the internal Kubernetes CA are only used and trusted within the Kubernetes cluster.
        • Ensuring the Kubernetes CA doesn't get added as a trusted CA for any systems outside the cluster.
        • Have two trusted key pairs, One for authenticating internal systems and a second for authenticating external systems.
    - Securing Pod communications:
	· If Pod don’t need to talk to API directly we can use this feature in spec: 
		apiVersion: v1
kind: Pod
metadata:
		  name: service-account-example-pod
spec:
		  serviceAccountName: some-service-account
  automountServiceAccountToken: false
	· If pod need to talk to API, we can use this features:
	        • expirationSeconds 
	        • audience
		apiVersion: v1
kind: Pod
metadata:
		  name: nginx
spec:
		  containers:
  - image: nginx
		    name: nginx
    volumeMounts:
    - mountPath: /var/run/secrets/tokens
		      name: vault-token
  serviceAccountName: my-pod
  volumes:
  - name: vault-token
		    projected:
      sources:
		      - serviceAccountToken:
          path: vault-token
          expirationSeconds: 3600
          audience: vault
2. Tampering (The act of changing something in a malicious way to cause Denial of service or Elevation of privilege):
    - Tampering with Kubernetes components:
            • Protecting against in-transit tampering with TLS 
    - Prevent tampering data at rest with:
            • Restrict access to the servers that are running Kubernetes components, especially control plane components
            • Restrict access to repositories that store Kubernetes configuration files
            • Only perform remote bootstrapping over SSH (remember to keep your SSH keys safe)
            • Always run SHA-2 checksums against downloads
            • Restrict access to your image registry and associated repositories
	· Configuring audit and alert for binaries and config files
		 auditctl -w /usr/bin/docker -p wxa -k audit-docker
    - Tampering with applications running on Kubernetes:
	Make pod filesystem readonly:
	
		apiVersion: v1
kind: Pod
metadata:
		  name: readonly-test
spec:
		  securityContext:
    readOnlyRootFilesystem: true
    allowedHostPaths:
		      - pathPrefix: "/test"
        readOnly: true
3. Repudiation (Creates doubt about something. We can make system non-repudiation by providing proof to prove below questions such as logs):
    - What happened
    - When it happened
    - Who made it happen  
    - Where it happened
    - Why it happened
    - How it happened

4. Information Disclosure (When sensitive data is leaked):
    - Protecting cluster data for example in cluster store by limiting and auditing. Don’t locking the house but leaving the keys in the door!
        • DEK or data encryption key (outside of cluster)
        • KEK or key encryption keys (outside of cluster)
        • HSM or Hardware security module
        • KMS
    - Protecting data in Pods using:
        • ConfigMaps
        • Secret

5. Denial of Service (Making something unavailable):
    - Protecting cluster resources against DoS attacks and botnets using:
	· Don’t have any single point of failure! Make control plane HA over multi-AZ
	· Having resource Limitation on below resources on namespaces:
            • CPU
            • Storage
            • Memory
            • use podPidsLimit feature in pods to protect any resource consuming attack such as fork bomb
		apiVersion: v1
kind: ResourceQuota
metadata:
		  name: pod-quota
		  namespace: skippy
spec:
		  hard:
    pods: "100"
        • Monitoring and alerting on API server requests.
        • Using firewalls
    - Protecting the cluster store against DoS attacks
        • Configure an HA etcd cluster with either 3 or 5 nodes (split brain/majority) to make it more resilient.
        • Configure monitoring and alerting of requests to etcd.
        • Isolate etcd at the network level so that only members of the control plane can interact with it.
    - Protecting application components against DoS attacks:
        • Define Kubernetes Network Policies to restrict Pod-to-Pod and Pod-to-external communications.
        • Utilize mutual TLS and API token-based authentication for application-level authentication (reject any unauthenticated requests).
	· Implementing application-layer authorization policies and the least privilege 

6. Elevation of Privilege (Gaining higher access than what is granted to cause damage or gain unauthorized access):
    - Safeguarding API server by running several authorization modes:
        - Role-based Access Control (RBAC): lets you restrict API operations to sub-sets of users 
        - Webhook: lets you offload authorization to an external REST-based policy engine. 
        - Node: is all about authorizing API requests made by kubelets (Nodes). 
    - Protecting Pods:
        - Preventing processes from running as root. root user of a container sometimes has unrestricted root access to the host. Use runAsUser for same replicas in container level instead of at the Pod level 

		apiVersion: v1
kind: Pod
metadata:
		  name: demo
spec:
		  securityContext:
    runAsUser: 1000
		  containers:
  - name: demo
		    image: example.io/simple:1.0
		
		
		apiVersion: v1
kind: Pod
metadata:
		  name: demo
spec:
		  securityContext:
    runAsUser: 1000
		  containers:
  - name: demo
		    image: example.io/simple:1.0
    securityContext:
		      runAsUser: 2000 
User namespaces is a Linux kernel technology that allows a process to run as root within a container but run as a different user outside the container. For example, a process can run as UID 0 (the root user) inside the container but get mapped to UID 1000
on the host. This can be a good solution for processes that need to run as root inside the container. However, you should check if it is fully-supported by your version of Kubernetes and your container runtime. 

        - Dropping capabilities
		apiVersion: v1
kind: Pod
metadata:
		  name: capability-test
spec:
		  containers:
  - name: demo
		    image: example.io/simple:1.0
    securityContext:
		      capabilities:
        add: ["NET_ADMIN", "CHOWN"]
		
        - Filtering syscalls
            Seccomp profile:
                Non-blocking
                Blocking
                Runtime Default
                Custom
        - Preventing privilege escalation
		apiVersion: v1
kind: Pod
metadata:
		  name: demo
spec:
		  containers:
  - name: demo
		    image: example.io/simple:1.0
    securityContext:
		      allowPrivilegeEscalation: false
7. Standardizing Pod Security with PSS and PSA
    - Pod Security Standards (PSS) for security policy
            • Privileged: wide-open allow-all policy.
            • Baseline: implements sensible defaults 
            • Restricted: highly restricted 
    - Pod Security Admission (PSA) for enforcing security policy. Has this modes:
            • Warn
            • Audit
            • Enforce
                kubectl label --overwrite ns psa-test pod-security.kubernetes.io/enforce=baseline

		apiVersion: v1
kind: Pod
metadata:
		  name: psa-pod
		  namespace: psa-test
spec:
		  containers:
  - name: psa-ctr
		    image: nginx
    securityContext:
		      privileged: true/false
		
    - Alternatives to Pod Security Admission to overcome PSS/PSA limitations:
            • OPA Gatekeeper 
            • Kubewarden
            • Kyverno

Cloud Native Security Whitepaper: https://github.com/cncf/tag- security/tree/main/security- whitepaper/v2 





Security in the software delivery pipeline:
    1. Policies forcing the use of signed images
    2. Network rules restricting which nodes can push and pull images 3. RBAC rules protecting image repositories
    4. Use of approved base images
    5. Image scanning for known vulnerabilities
    6. Promotion and quarantining of images based on scan results
    7. Review and scan infrastructure-as-code configuration files
