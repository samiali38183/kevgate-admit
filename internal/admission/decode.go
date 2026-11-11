// Package admission decodes AdmissionReview v1 requests, extracts container
// images from supported workload kinds and renders the webhook response.
package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// Errors returned by decoding and extraction.
var (
	ErrBadRequest  = errors.New("bad admission review")
	ErrUnsupported = errors.New("unsupported resource")
)

const maxImages = 128

// DecodeReview strictly decodes an AdmissionReview v1: unknown fields in the
// envelope, trailing data, a wrong apiVersion or kind and a missing request or
// UID are all rejected. The embedded object is decoded later, leniently,
// because the API server has already validated it against its own schema.
func DecodeReview(body []byte) (*admissionv1.AdmissionReview, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var rev admissionv1.AdmissionReview
	if err := dec.Decode(&rev); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrBadRequest)
	}
	if rev.APIVersion != "admission.k8s.io/v1" || rev.Kind != "AdmissionReview" {
		return nil, fmt.Errorf("%w: expected admission.k8s.io/v1 AdmissionReview", ErrBadRequest)
	}
	if rev.Request == nil || rev.Request.UID == "" {
		return nil, fmt.Errorf("%w: missing request or uid", ErrBadRequest)
	}
	return &rev, nil
}

// Workload describes what a request would run.
type Workload struct {
	Kind   string
	Name   string
	Images []string // unique, in container, init container, ephemeral container order
}

// Extract returns the images of the object in the request. For UPDATE it
// returns only images that are not already present in the old object, so
// routine updates of a running workload are not re-judged against evidence
// that has changed since it was admitted.
func Extract(req *admissionv1.AdmissionRequest) (*Workload, error) {
	if req.SubResource != "" && req.SubResource != "ephemeralcontainers" {
		return nil, fmt.Errorf("%w: subresource %q", ErrUnsupported, req.SubResource)
	}
	spec, name, err := podSpecOf(req.Kind.Group, req.Kind.Kind, req.Object.Raw)
	if err != nil {
		return nil, err
	}
	w := &Workload{Kind: req.Kind.Kind, Name: name}
	imgs := imagesOf(spec)
	if req.Operation == admissionv1.Update && len(req.OldObject.Raw) > 0 {
		if oldSpec, _, oerr := podSpecOf(req.Kind.Group, req.Kind.Kind, req.OldObject.Raw); oerr == nil {
			old := map[string]bool{}
			for _, i := range imagesOf(oldSpec) {
				old[i] = true
			}
			kept := imgs[:0:0]
			for _, i := range imgs {
				if !old[i] {
					kept = append(kept, i)
				}
			}
			imgs = kept
		}
	}
	if len(imgs) > maxImages {
		return nil, fmt.Errorf("%w: more than %d distinct images", ErrBadRequest, maxImages)
	}
	w.Images = imgs
	return w, nil
}

func podSpecOf(group, kind string, raw []byte) (*corev1.PodSpec, string, error) {
	if len(raw) == 0 {
		return nil, "", fmt.Errorf("%w: empty object", ErrBadRequest)
	}
	var err error
	switch {
	case group == "" && kind == "Pod":
		var o corev1.Pod
		if err = json.Unmarshal(raw, &o); err == nil {
			return &o.Spec, o.Name, nil
		}
	case group == "apps" && kind == "Deployment":
		var o appsv1.Deployment
		if err = json.Unmarshal(raw, &o); err == nil {
			return &o.Spec.Template.Spec, o.Name, nil
		}
	case group == "apps" && kind == "StatefulSet":
		var o appsv1.StatefulSet
		if err = json.Unmarshal(raw, &o); err == nil {
			return &o.Spec.Template.Spec, o.Name, nil
		}
	case group == "apps" && kind == "DaemonSet":
		var o appsv1.DaemonSet
		if err = json.Unmarshal(raw, &o); err == nil {
			return &o.Spec.Template.Spec, o.Name, nil
		}
	case group == "batch" && kind == "Job":
		var o batchv1.Job
		if err = json.Unmarshal(raw, &o); err == nil {
			return &o.Spec.Template.Spec, o.Name, nil
		}
	case group == "batch" && kind == "CronJob":
		var o batchv1.CronJob
		if err = json.Unmarshal(raw, &o); err == nil {
			return &o.Spec.JobTemplate.Spec.Template.Spec, o.Name, nil
		}
	default:
		return nil, "", fmt.Errorf("%w: %s/%s", ErrUnsupported, group, kind)
	}
	return nil, "", fmt.Errorf("%w: decoding %s: %w", ErrBadRequest, kind, err)
}

func imagesOf(spec *corev1.PodSpec) []string {
	seen := map[string]bool{}
	var out []string
	add := func(i string) {
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	for _, c := range spec.Containers {
		add(c.Image)
	}
	for _, c := range spec.InitContainers {
		add(c.Image)
	}
	for _, c := range spec.EphemeralContainers {
		add(c.Image)
	}
	return out
}
