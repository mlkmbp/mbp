<script setup lang="ts">
import { ref, watch } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import api from '@/api'

/** —— v-model 协议 —— */
const props = defineProps<{ modelValue: boolean }>()
const emit  = defineEmits<{ (e:'update:modelValue', v:boolean): void }>()
const visible = ref<boolean>(props.modelValue)
watch(() => props.modelValue, v => (visible.value = v))
watch(visible, v => emit('update:modelValue', v))

/** —— 表单 —— */
const formRef = ref<FormInstance>()
const form = ref({
  old_password: '',
  new_password: '',
  confirm: ''
})

const rules: FormRules = {
  old_password: [
    { required: true, message: '请输入原密码', trigger: 'blur' },
    { min: 6, max: 64, message: '长度 6-64 位', trigger: 'blur' },
    {
      validator: (_r, v, cb) => {
        if (v.trim() !== v) return cb(new Error('首尾不能有空格'))
        cb()
      }, trigger: 'blur'
    }
  ],
  new_password: [
    { required: true, message: '请输入新密码', trigger: ['blur','change'] },
    { min: 6, max: 64, message: '长度 6-64 位', trigger: 'blur' },
    {
      validator: (_r, v, cb) => {
        if (v.trim() !== v) return cb(new Error('首尾不能有空格'))
        cb()
      }, trigger: 'blur'
    }
  ],
  confirm: [
    { required: true, message: '请再次输入新密码', trigger: ['blur','change'] },
    {
      validator: (_r, v, cb) => {
        if (!v) return cb(new Error('确认新密码不能为空'))
        if (v !== form.value.new_password) return cb(new Error('两次输入不一致'))
        cb()
      }, trigger: ['blur','change']
    }
  ]
}

/** 新密码变化时，联动校验确认字段，避免不同步 */
watch(() => form.value.new_password, () => {
  formRef.value?.validateField('confirm')
})

async function submit() {
  const ok = await formRef.value?.validate()
  if (!ok) return
  try {
    await api.put('/me/password', {
      old_password: form.value.old_password,
      new_password: form.value.new_password,
      confirm: form.value.confirm
    })
    ElMessage.success('修改成功，请使用新密码登录')
    visible.value = false  // 触发 v-model 同步关闭
    localStorage.removeItem('token')
    location.href = '/login'
  } catch (e:any) {
    // ElMessage.error(e?.response?.data?.error || e?.message || '修改失败，请重试')
  }
}

function onClose() {
  // 关闭清空 + 清校验
  form.value = { old_password: '', new_password: '', confirm: '' }
  formRef.value?.clearValidate()
}
</script>

<template>
  <el-dialog v-model="visible" title="修改密码" width="420px" @closed="onClose">
    <el-form ref="formRef" :model="form" :rules="rules" label-width="100px">
      <el-form-item label="原密码" prop="old_password">
        <el-input
          v-model="form.old_password"
          type="password" show-password
          autocomplete="current-password"
          @keyup.enter="submit"
        />
      </el-form-item>
      <el-form-item label="新密码" prop="new_password">
        <el-input
          v-model="form.new_password"
          type="password" show-password
          autocomplete="new-password"
          @keyup.enter="submit"
        />
      </el-form-item>
      <el-form-item label="确认新密码" prop="confirm">
        <el-input
          v-model="form.confirm"
          type="password" show-password
          autocomplete="new-password"
          @keyup.enter="submit"
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="visible=false">取消</el-button>
      <el-button type="primary" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>
