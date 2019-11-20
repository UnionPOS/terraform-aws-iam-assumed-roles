locals {
  readonly_user_names = length(var.readonly_user_names) > 0 ? true : false
  role_readonly_name  = join("", aws_iam_role.readonly.*.name)
}

module "readonly_label" {
  source     = "git::https://github.com/UnionPOS/terraform-null-label.git?ref=up"
  namespace  = var.namespace
  stage      = var.stage
  name       = var.readonly_name
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

resource "aws_iam_policy" "manage_mfa_readonly" {
  count       = var.enabled ? 1 : 0
  name        = "${module.readonly_label.id}-permit-mfa"
  description = "Allow readonly users to manage Virtual MFA Devices"
  policy      = join("", data.aws_iam_policy_document.manage_mfa.*.json)
}

resource "aws_iam_policy" "allow_change_password_readonly" {
  count       = var.enabled ? 1 : 0
  name        = "${module.readonly_label.id}-permit-change-password"
  description = "Allow readonly users to change password"
  policy = join(
    "",
    data.aws_iam_policy_document.allow_change_password.*.json,
  )
}

resource "aws_iam_policy" "allow_key_management_readonly" {
  name        = "${module.readonly_label.id}-permit-manage-keys"
  description = "Allow readonly users to manage their own access keys"
  policy      = data.aws_iam_policy_document.allow_key_management.json
}

data "aws_iam_policy_document" "assume_role_readonly" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [join("", aws_iam_role.readonly.*.arn)]
  }
}

resource "aws_iam_policy" "assume_role_readonly" {
  count       = var.enabled ? 1 : 0
  name        = "${module.readonly_label.id}-permit-assume-role"
  description = "Allow assuming readonly role"
  policy      = join("", data.aws_iam_policy_document.assume_role_readonly.*.json)
}

## create role
resource "aws_iam_role" "readonly" {
  count              = var.enabled ? 1 : 0
  name               = module.readonly_label.id
  assume_role_policy = join("", data.aws_iam_policy_document.role_trust.*.json)
}

resource "aws_iam_role_policy_attachment" "readonly" {
  count      = var.enabled ? 1 : 0
  role       = join("", aws_iam_role.readonly.*.name)
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_group" "readonly" {
  count = var.groups_enabled ? 1 : 0
  name  = module.readonly_label.id
}

resource "aws_iam_group_policy_attachment" "assume_role_readonly" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.readonly.*.name)
  policy_arn = join("", aws_iam_policy.assume_role_readonly.*.arn)
}

resource "aws_iam_group_policy_attachment" "manage_mfa_readonly" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.readonly.*.name)
  policy_arn = join("", aws_iam_policy.manage_mfa_readonly.*.arn)
}

resource "aws_iam_group_policy_attachment" "allow_change_password_readonly" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.readonly.*.name)
  policy_arn = join("", aws_iam_policy.allow_change_password_readonly.*.arn)
}

resource "aws_iam_group_policy_attachment" "key_management_readonly" {
  count      = var.groups_enabled ? 1 : 0
  group      = aws_iam_group.readonly[0].name
  policy_arn = aws_iam_policy.allow_key_management_readonly.arn
}

resource "aws_iam_group_membership" "readonly" {
  count = var.groups_enabled && local.readonly_user_names ? 1 : 0
  name  = module.readonly_label.id
  group = join("", aws_iam_group.readonly.*.id)
  users = var.readonly_user_names
}

