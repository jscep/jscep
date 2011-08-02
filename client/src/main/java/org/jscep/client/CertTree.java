package org.jscep.client;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

// this is a classic pattern.
// should CertTree implement Node too?
public class CertTree {
    private Node root;

    public void add(X509Certificate cert) {
        Node node = new Node(cert);
        if (root == null) {
            root = node;
        } else if (root.add(node)) {
            // root certificate issued certificate in arg, or something in the tree
        } else if (isSigner(cert, root.getCert())) {
            // certificate in arg issued root certificate
            node.add(root);
            root = node;
        } else {
            // certificate has no relationship to root certificate
            // iterate through tree now?
        }
    }

    public String toString() {
        return root.toString();
    }

    private static boolean isSigner(X509Certificate signer, X509Certificate signed) {
        try {
            signed.verify(signer.getPublicKey());

            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    class Node {
        private final Collection<Node> children;
        private final X509Certificate cert;

        public Node(X509Certificate cert) {
            this.cert = cert;
            this.children = new LinkedList<Node>();
        }

        public X509Certificate getCert() {
            return cert;
        }

        public boolean add(Node node) {
            X509Certificate nodeCert = node.getCert();

            if (isSigner(cert, nodeCert)) {
                children.add(node);

                return true;
            } else {
                for (Node childNode : children) {
                    if (childNode.add(node)) {
                        return true;
                    }
                }
            }

            return false;
        }

        public Collection<Node> getChildren() {
            return children;
        }

        public String toString() {
            if (children.isEmpty() == false) {
                return cert.getSerialNumber() + "[" + children + "]";
            } else {
                return cert.getSerialNumber().toString();
            }
        }
    }
}
