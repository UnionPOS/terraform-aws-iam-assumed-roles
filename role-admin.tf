locals {
  admin_user_names = length(var.admin_user_names) > 0 ? true : false
  role_admin_name  = join("", aws_iam_role.admin.*.name)
}

module "admin_label" {
  source     = "git::https://github.com/UnionPOS/terraform-null-label.git?ref=up"
  namespace  = var.namespace
  stage      = var.stage
  name       = var.admin_name
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

resource "aws_iam_policy" "manage_mfa_admin" {
  count       = var.enabled ? 1 : 0
  name        = "${module.admin_label.id}-permit-mfa"
  description = "Allow admin users to manage Virtual MFA Devices"
  policy      = join("", data.aws_iam_policy_document.manage_mfa.*.json)
}

resource "aws_iam_policy" "allow_change_password_admin" {
  count       = var.enabled ? 1 : 0
  name        = "${module.admin_label.id}-permit-change-password"
  description = "Allow admin users to change password"
  policy = join(
    "",
    data.aws_iam_policy_document.allow_change_password.*.json,
  )
}

resource "aws_iam_policy" "allow_key_management_admin" {
  name        = "${module.admin_label.id}-allow-key-management"
  description = "Allow admin users to manage their own access keys"
  policy      = data.aws_iam_policy_document.allow_key_management.json
}

data "aws_iam_policy_document" "assume_role_admin" {
  count = var.enabled ? 1 : 0

  statement {
    actions   = ["sts:AssumeRole"]
    resources = [join("", aws_iam_role.admin.*.arn)]
  }
}

resource "aws_iam_policy" "assume_role_admin" {
  count       = var.enabled ? 1 : 0
  name        = "${module.admin_label.id}-permit-assume-role"
  description = "Allow assuming admin role"
  policy      = join("", data.aws_iam_policy_document.assume_role_admin.*.json)
}

resource "aws_iam_role" "admin" {
  count              = var.enabled ? 1 : 0
  name               = module.admin_label.id
  assume_role_policy = join("", data.aws_iam_policy_document.role_trust.*.json)
}

resource "aws_iam_role_policy_attachment" "admin" {
  count      = var.enabled ? 1 : 0
  role       = join("", aws_iam_role.admin.*.name)
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group" "admin" {
  count = var.groups_enabled ? 1 : 0
  name  = module.admin_label.id
}

resource "aws_iam_group_policy_attachment" "assume_role_admin" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.admin.*.name)
  policy_arn = join("", aws_iam_policy.assume_role_admin.*.arn)
}

resource "aws_iam_group_policy_attachment" "manage_mfa_admin" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.admin.*.name)
  policy_arn = join("", aws_iam_policy.manage_mfa_admin.*.arn)
}

resource "aws_iam_group_policy_attachment" "allow_chage_password_admin" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.admin.*.name)
  policy_arn = join("", aws_iam_policy.allow_change_password_admin.*.arn)
}

resource "aws_iam_group_policy_attachment" "key_management_admin" {
  count      = var.groups_enabled ? 1 : 0
  group      = aws_iam_group.admin[0].name
  policy_arn = aws_iam_policy.allow_key_management_admin.arn
}

resource "aws_iam_group_membership" "admin" {
  count = var.groups_enabled && local.admin_user_names ? 1 : 0
  name  = module.admin_label.id
  group = join("", aws_iam_group.admin.*.id)
  users = var.admin_user_names
}

